//! Canonical binary encoding for evaluator checkpoints and node state.
//!
//! Decoding is bounded and reconstructs a fresh evaluator before verifying
//! that re-encoding produces the exact submitted bytes.

use super::*;

pub(super) fn encode_node_state(
    state: &EvaluatorNodeState,
) -> Result<Vec<u8>, SignalEvaluationError> {
    let mut writer = EvaluatorWriter::default();
    match state {
        EvaluatorNodeState::Hysteresis {
            value,
            last_transition_nanos,
        } => {
            writer.byte(0);
            writer.boolean(*value);
            writer.u64(*last_transition_nanos);
        }
        EvaluatorNodeState::Debounce {
            committed,
            candidate,
            candidate_since_nanos,
        } => {
            writer.byte(1);
            writer.value(committed)?;
            writer.optional_value(candidate.as_ref())?;
            writer.optional_u64(*candidate_since_nanos);
        }
        EvaluatorNodeState::Integrator {
            accumulator,
            pending,
            previous_input,
            last_nanos,
        } => {
            writer.byte(2);
            writer.value(accumulator)?;
            writer.value(pending)?;
            writer.optional_value(previous_input.as_ref())?;
            writer.optional_u64(*last_nanos);
        }
        EvaluatorNodeState::LeakyIntegrator {
            accumulator,
            previous_input,
            last_nanos,
        } => {
            writer.byte(3);
            writer.value(accumulator)?;
            writer.optional_value(previous_input.as_ref())?;
            writer.optional_u64(*last_nanos);
        }
        EvaluatorNodeState::FiniteStateMachine { state, timers } => {
            writer.byte(4);
            writer.id(state)?;
            writer.count(timers.len())?;
            for (timer, deadline) in timers {
                writer.id(timer)?;
                writer.u64(*deadline);
            }
        }
        EvaluatorNodeState::MarkovChain {
            state,
            transition_sequence,
        } => {
            writer.byte(5);
            writer.id(state)?;
            writer.u64(*transition_sequence);
        }
        EvaluatorNodeState::BurstProcess {
            bad,
            transition_sequence,
        } => {
            writer.byte(6);
            writer.boolean(*bad);
            writer.u64(*transition_sequence);
        }
        EvaluatorNodeState::Counter { count } => {
            writer.byte(7);
            writer.u64(*count);
        }
        EvaluatorNodeState::QueueModel {
            backlog,
            service_remainder,
            last_nanos,
        } => {
            writer.byte(8);
            writer.u32(*backlog);
            writer.u64(*service_remainder);
            writer.optional_u64(*last_nanos);
        }
    }
    Ok(writer.bytes)
}

#[derive(Default)]
pub(super) struct EvaluatorWriter {
    pub(super) bytes: Vec<u8>,
}

impl EvaluatorWriter {
    pub(super) fn byte(&mut self, value: u8) {
        self.bytes.push(value);
    }

    pub(super) fn boolean(&mut self, value: bool) {
        self.byte(u8::from(value));
    }

    pub(super) fn u16(&mut self, value: u16) {
        self.bytes.extend_from_slice(&value.to_be_bytes());
    }

    pub(super) fn u32(&mut self, value: u32) {
        self.bytes.extend_from_slice(&value.to_be_bytes());
    }

    pub(super) fn u64(&mut self, value: u64) {
        self.bytes.extend_from_slice(&value.to_be_bytes());
    }

    pub(super) fn i64(&mut self, value: i64) {
        self.bytes.extend_from_slice(&value.to_be_bytes());
    }

    pub(super) fn count(&mut self, value: usize) -> Result<(), SignalEvaluationError> {
        self.u32(u32::try_from(value).map_err(|_| SignalEvaluationError::CheckpointLimit)?);
        Ok(())
    }

    pub(super) fn blob(&mut self, value: &[u8]) -> Result<(), SignalEvaluationError> {
        self.count(value.len())?;
        self.bytes.extend_from_slice(value);
        Ok(())
    }

    pub(super) fn id(&mut self, value: &SignalId) -> Result<(), SignalEvaluationError> {
        self.blob(value.as_str().as_bytes())
    }

    pub(super) fn optional_u64(&mut self, value: Option<u64>) {
        match value {
            Some(value) => {
                self.byte(1);
                self.u64(value);
            }
            None => self.byte(0),
        }
    }

    pub(super) fn value(&mut self, value: &SignalValue) -> Result<(), SignalEvaluationError> {
        self.blob(&encode_signal_value(value).map_err(SignalEvaluationError::Trace)?)
    }

    pub(super) fn optional_value(
        &mut self,
        value: Option<&SignalValue>,
    ) -> Result<(), SignalEvaluationError> {
        match value {
            Some(value) => {
                self.byte(1);
                self.value(value)
            }
            None => {
                self.byte(0);
                Ok(())
            }
        }
    }

    pub(super) fn evaluated(
        &mut self,
        value: &EvaluatedSignal,
    ) -> Result<(), SignalEvaluationError> {
        match value {
            EvaluatedSignal::Inactive => {
                self.byte(0);
                Ok(())
            }
            EvaluatedSignal::Value(value) => {
                self.byte(1);
                self.value(value)
            }
        }
    }

    pub(super) fn coordinate(
        &mut self,
        coordinate: &SignalCoordinate,
    ) -> Result<(), SignalEvaluationError> {
        match coordinate {
            SignalCoordinate::VirtualTime { nanos } => {
                self.byte(0);
                self.u64(*nanos);
            }
            SignalCoordinate::NodeCounter {
                node,
                retired_instructions,
            } => {
                self.byte(1);
                self.id(node)?;
                self.u64(*retired_instructions);
            }
            SignalCoordinate::Operation {
                adapter,
                target,
                operation,
                producer_sequence,
                suboperation,
            } => {
                self.byte(2);
                self.id(adapter)?;
                self.id(target)?;
                self.id(operation)?;
                self.u64(*producer_sequence);
                self.u32(*suboperation);
            }
            SignalCoordinate::Spatial {
                frame,
                x_mm,
                y_mm,
                z_mm,
                yaw_mdeg,
                pitch_mdeg,
                roll_mdeg,
            } => {
                self.byte(3);
                self.id(frame)?;
                for value in [x_mm, y_mm, z_mm, yaw_mdeg, pitch_mdeg, roll_mdeg] {
                    self.i64(*value);
                }
            }
            SignalCoordinate::Event { parent, sequence } => {
                self.byte(4);
                self.coordinate(parent)?;
                self.u64(*sequence);
            }
            SignalCoordinate::State {
                adapter,
                target,
                boundary_sequence,
            } => {
                self.byte(5);
                self.id(adapter)?;
                self.id(target)?;
                self.u64(*boundary_sequence);
            }
        }
        Ok(())
    }
}

pub(super) struct EvaluatorReader<'a> {
    bytes: &'a [u8],
    cursor: usize,
}

impl<'a> EvaluatorReader<'a> {
    pub(super) const fn new(bytes: &'a [u8]) -> Self {
        Self { bytes, cursor: 0 }
    }

    pub(super) fn take(&mut self, length: usize) -> Result<&'a [u8], SignalEvaluationError> {
        let end = self
            .cursor
            .checked_add(length)
            .ok_or(SignalEvaluationError::MalformedCheckpoint)?;
        let value = self
            .bytes
            .get(self.cursor..end)
            .ok_or(SignalEvaluationError::MalformedCheckpoint)?;
        self.cursor = end;
        Ok(value)
    }

    pub(super) fn finish(&self) -> Result<(), SignalEvaluationError> {
        if self.cursor == self.bytes.len() {
            Ok(())
        } else {
            Err(SignalEvaluationError::MalformedCheckpoint)
        }
    }

    pub(super) fn byte(&mut self) -> Result<u8, SignalEvaluationError> {
        Ok(self.take(1)?[0])
    }

    pub(super) fn boolean(&mut self) -> Result<bool, SignalEvaluationError> {
        match self.byte()? {
            0 => Ok(false),
            1 => Ok(true),
            _ => Err(SignalEvaluationError::MalformedCheckpoint),
        }
    }

    pub(super) fn u16(&mut self) -> Result<u16, SignalEvaluationError> {
        let bytes = self
            .take(2)?
            .try_into()
            .map_err(|_| SignalEvaluationError::MalformedCheckpoint)?;
        Ok(u16::from_be_bytes(bytes))
    }

    pub(super) fn u32(&mut self) -> Result<u32, SignalEvaluationError> {
        let bytes = self
            .take(4)?
            .try_into()
            .map_err(|_| SignalEvaluationError::MalformedCheckpoint)?;
        Ok(u32::from_be_bytes(bytes))
    }

    pub(super) fn u64(&mut self) -> Result<u64, SignalEvaluationError> {
        let bytes = self
            .take(8)?
            .try_into()
            .map_err(|_| SignalEvaluationError::MalformedCheckpoint)?;
        Ok(u64::from_be_bytes(bytes))
    }

    pub(super) fn i64(&mut self) -> Result<i64, SignalEvaluationError> {
        let bytes = self
            .take(8)?
            .try_into()
            .map_err(|_| SignalEvaluationError::MalformedCheckpoint)?;
        Ok(i64::from_be_bytes(bytes))
    }

    pub(super) fn count(&mut self, maximum: usize) -> Result<usize, SignalEvaluationError> {
        let value =
            usize::try_from(self.u32()?).map_err(|_| SignalEvaluationError::CheckpointLimit)?;
        if value > maximum {
            return Err(SignalEvaluationError::CheckpointLimit);
        }
        Ok(value)
    }

    pub(super) fn blob(&mut self, maximum: usize) -> Result<&'a [u8], SignalEvaluationError> {
        let length = self.count(maximum)?;
        self.take(length)
    }

    pub(super) fn id(&mut self) -> Result<SignalId, SignalEvaluationError> {
        let text = std::str::from_utf8(self.blob(FAULT_ID_MAX_BYTES)?)
            .map_err(|_| SignalEvaluationError::MalformedCheckpoint)?;
        SignalId::parse(text).map_err(SignalEvaluationError::Program)
    }

    pub(super) fn hash(&mut self) -> Result<ContentHash, SignalEvaluationError> {
        let bytes = self
            .take(32)?
            .try_into()
            .map_err(|_| SignalEvaluationError::MalformedCheckpoint)?;
        Ok(ContentHash { bytes })
    }

    pub(super) fn optional_u64(&mut self) -> Result<Option<u64>, SignalEvaluationError> {
        match self.byte()? {
            0 => Ok(None),
            1 => Ok(Some(self.u64()?)),
            _ => Err(SignalEvaluationError::MalformedCheckpoint),
        }
    }

    pub(super) fn value(&mut self) -> Result<SignalValue, SignalEvaluationError> {
        decode_signal_value(self.blob(HARD_SIGNAL_EVENT_BYTES)?)
            .map_err(SignalEvaluationError::Trace)
    }

    pub(super) fn optional_value(&mut self) -> Result<Option<SignalValue>, SignalEvaluationError> {
        match self.byte()? {
            0 => Ok(None),
            1 => Ok(Some(self.value()?)),
            _ => Err(SignalEvaluationError::MalformedCheckpoint),
        }
    }

    pub(super) fn evaluated(&mut self) -> Result<EvaluatedSignal, SignalEvaluationError> {
        match self.byte()? {
            0 => Ok(EvaluatedSignal::Inactive),
            1 => Ok(EvaluatedSignal::Value(self.value()?)),
            _ => Err(SignalEvaluationError::MalformedCheckpoint),
        }
    }

    pub(super) fn coordinate(
        &mut self,
        depth: u8,
    ) -> Result<SignalCoordinate, SignalEvaluationError> {
        if depth > 8 {
            return Err(SignalEvaluationError::MalformedCheckpoint);
        }
        match self.byte()? {
            0 => Ok(SignalCoordinate::VirtualTime { nanos: self.u64()? }),
            1 => Ok(SignalCoordinate::NodeCounter {
                node: self.id()?,
                retired_instructions: self.u64()?,
            }),
            2 => Ok(SignalCoordinate::Operation {
                adapter: self.id()?,
                target: self.id()?,
                operation: self.id()?,
                producer_sequence: self.u64()?,
                suboperation: self.u32()?,
            }),
            3 => Ok(SignalCoordinate::Spatial {
                frame: self.id()?,
                x_mm: self.i64()?,
                y_mm: self.i64()?,
                z_mm: self.i64()?,
                yaw_mdeg: self.i64()?,
                pitch_mdeg: self.i64()?,
                roll_mdeg: self.i64()?,
            }),
            4 => Ok(SignalCoordinate::Event {
                parent: Box::new(self.coordinate(depth + 1)?),
                sequence: self.u64()?,
            }),
            5 => Ok(SignalCoordinate::State {
                adapter: self.id()?,
                target: self.id()?,
                boundary_sequence: self.u64()?,
            }),
            _ => Err(SignalEvaluationError::MalformedCheckpoint),
        }
    }
}

pub(super) fn decode_node_state(
    bytes: &[u8],
    specification: &StatefulSignalSpecification,
) -> Result<EvaluatorNodeState, SignalEvaluationError> {
    let mut reader = EvaluatorReader::new(bytes);
    let state = match (reader.byte()?, specification) {
        (0, StatefulSignalSpecification::Hysteresis { .. }) => EvaluatorNodeState::Hysteresis {
            value: reader.boolean()?,
            last_transition_nanos: reader.u64()?,
        },
        (1, StatefulSignalSpecification::Debounce { .. }) => EvaluatorNodeState::Debounce {
            committed: reader.value()?,
            candidate: reader.optional_value()?,
            candidate_since_nanos: reader.optional_u64()?,
        },
        (2, StatefulSignalSpecification::Integrator { .. }) => EvaluatorNodeState::Integrator {
            accumulator: reader.value()?,
            pending: reader.value()?,
            previous_input: reader.optional_value()?,
            last_nanos: reader.optional_u64()?,
        },
        (3, StatefulSignalSpecification::LeakyIntegrator { .. }) => {
            EvaluatorNodeState::LeakyIntegrator {
                accumulator: reader.value()?,
                previous_input: reader.optional_value()?,
                last_nanos: reader.optional_u64()?,
            }
        }
        (4, StatefulSignalSpecification::FiniteStateMachine { states, .. }) => {
            let state = reader.id()?;
            if !states.contains(&state) {
                return Err(SignalEvaluationError::InvalidState);
            }
            let count = reader.count(HARD_SIGNAL_STATES_PER_NODE_LIMIT as usize)?;
            let mut timers = BTreeMap::new();
            for _ in 0..count {
                let timer = reader.id()?;
                let deadline = reader.u64()?;
                if timers.insert(timer, deadline).is_some() {
                    return Err(SignalEvaluationError::MalformedCheckpoint);
                }
            }
            EvaluatorNodeState::FiniteStateMachine { state, timers }
        }
        (5, StatefulSignalSpecification::MarkovChain { states, .. }) => {
            let state = reader.id()?;
            if !states.contains(&state) {
                return Err(SignalEvaluationError::InvalidState);
            }
            EvaluatorNodeState::MarkovChain {
                state,
                transition_sequence: reader.u64()?,
            }
        }
        (6, StatefulSignalSpecification::BurstProcess { .. }) => EvaluatorNodeState::BurstProcess {
            bad: reader.boolean()?,
            transition_sequence: reader.u64()?,
        },
        (7, StatefulSignalSpecification::Counter { maximum, .. }) => {
            let count = reader.u64()?;
            if count > *maximum {
                return Err(SignalEvaluationError::InvalidState);
            }
            EvaluatorNodeState::Counter { count }
        }
        (8, StatefulSignalSpecification::QueueModel { capacity, .. }) => {
            let backlog = reader.u32()?;
            let service_remainder = reader.u64()?;
            if backlog > *capacity || service_remainder >= 1_000_000_000 {
                return Err(SignalEvaluationError::InvalidState);
            }
            EvaluatorNodeState::QueueModel {
                backlog,
                service_remainder,
                last_nanos: reader.optional_u64()?,
            }
        }
        _ => return Err(SignalEvaluationError::StateVariantMismatch),
    };
    reader.finish()?;
    if encode_node_state(&state)? != bytes {
        return Err(SignalEvaluationError::NonCanonicalCheckpoint);
    }
    Ok(state)
}

pub(super) fn decode_evaluator_checkpoint<'a>(
    program: &'a SignalProgram,
    artifacts: &'a dyn SignalArtifactProvider,
    checkpoint: &SignalEvaluatorCheckpoint,
    resource_limits: FaultResourceLimits,
) -> Result<SignalEvaluator<'a>, SignalEvaluationError> {
    let mut reader = EvaluatorReader::new(&checkpoint.bytes);
    if reader.take(EVALUATOR_CHECKPOINT_MAGIC.len())? != EVALUATOR_CHECKPOINT_MAGIC
        || reader.u16()? != SIGNAL_EVALUATOR_VERSION
        || reader.hash()? != program.id()
    {
        return Err(SignalEvaluationError::CheckpointIdentityMismatch);
    }
    let telemetry_count = reader.count(HARD_SIGNAL_BOUNDARY_ITEMS)?;
    let mut telemetry = BTreeMap::new();
    for _ in 0..telemetry_count {
        let key = SignalTelemetryKey {
            adapter: reader.id()?,
            target: reader.id()?,
            field: reader.id()?,
        };
        let value = reader.value()?;
        if telemetry.insert(key, value).is_some() {
            return Err(SignalEvaluationError::MalformedCheckpoint);
        }
    }
    let expected_state = program
        .nodes()
        .iter()
        .filter_map(|node| match &node.kind {
            SignalNodeKind::Stateful {
                specification,
                state_bytes,
            } => Some((node.id.clone(), (specification, *state_bytes))),
            _ => None,
        })
        .collect::<BTreeMap<_, _>>();
    let state_count = reader.count(expected_state.len())?;
    if state_count != expected_state.len() {
        return Err(SignalEvaluationError::IncompleteCheckpoint);
    }
    let mut state = BTreeMap::new();
    for _ in 0..state_count {
        let id = reader.id()?;
        let (specification, declared) = expected_state
            .get(&id)
            .map(|(specification, declared)| (*specification, *declared))
            .ok_or_else(|| SignalEvaluationError::MissingState(id.clone()))?;
        let maximum = usize::try_from(declared)
            .unwrap_or(HARD_SIGNAL_NODE_RUNTIME_BYTES)
            .min(HARD_SIGNAL_NODE_RUNTIME_BYTES);
        let bytes = reader.blob(maximum)?;
        let decoded = decode_node_state(bytes, specification)?;
        if state.insert(id, decoded).is_some() {
            return Err(SignalEvaluationError::MalformedCheckpoint);
        }
    }
    if state.keys().collect::<Vec<_>>() != expected_state.keys().collect::<Vec<_>>() {
        return Err(SignalEvaluationError::IncompleteCheckpoint);
    }
    let coordinate_count = reader.count(state.len())?;
    let mut state_coordinates = BTreeMap::new();
    for _ in 0..coordinate_count {
        let id = reader.id()?;
        let coordinate = reader.coordinate(0)?;
        let sequence = reader.u64()?;
        if !state.contains_key(&id)
            || state_coordinates
                .insert(id, (coordinate, sequence))
                .is_some()
        {
            return Err(SignalEvaluationError::MalformedCheckpoint);
        }
    }
    let limits = history_limits(program);
    let history_node_count = reader.count(limits.len())?;
    let mut history = BTreeMap::new();
    let mut retained_history = 0_usize;
    for _ in 0..history_node_count {
        let id = reader.id()?;
        let limit = limits
            .get(&id)
            .copied()
            .ok_or_else(|| SignalEvaluationError::UnexpectedHistory(id.clone()))?;
        let count = reader.count(limit)?;
        retained_history = retained_history
            .checked_add(count)
            .ok_or(SignalEvaluationError::CheckpointLimit)?;
        if retained_history > HARD_SIGNAL_HISTORY_ENTRIES {
            return Err(SignalEvaluationError::CheckpointLimit);
        }
        let node = program
            .nodes()
            .iter()
            .find(|node| node.id == id)
            .ok_or_else(|| SignalEvaluationError::MissingNode(id.clone()))?;
        let mut entries = VecDeque::with_capacity(count);
        for _ in 0..count {
            let coordinate = reader.coordinate(0)?;
            let same_coordinate_sequence = reader.u64()?;
            let output = reader.evaluated()?;
            if coordinate_domain_runtime(&coordinate) != node.domain
                || entries.back().is_some_and(|prior: &HistoryEntry| {
                    (&prior.coordinate, prior.same_coordinate_sequence)
                        >= (&coordinate, same_coordinate_sequence)
                })
            {
                return Err(SignalEvaluationError::MalformedCheckpoint);
            }
            validate_evaluated_shape(node, &output)?;
            entries.push_back(HistoryEntry {
                coordinate,
                same_coordinate_sequence,
                output,
            });
        }
        if history.insert(id, entries).is_some() {
            return Err(SignalEvaluationError::MalformedCheckpoint);
        }
    }
    // Boundary evaluation consumes state-machine emissions before checkpointing;
    // retained pending history is therefore not part of the continuation.
    let emitted_count = reader.count(0)?;
    let mut emitted_events = Vec::with_capacity(emitted_count);
    for _ in 0..emitted_count {
        let node = reader.id()?;
        if !state.contains_key(&node) {
            return Err(SignalEvaluationError::MalformedCheckpoint);
        }
        emitted_events.push(StatefulSignalEvent {
            node,
            variant: reader.id()?,
            coordinate: reader.coordinate(0)?,
            same_coordinate_sequence: reader.u64()?,
        });
    }
    reader.finish()?;
    let evaluator = SignalEvaluator {
        program,
        artifacts,
        boundary: SignalBoundarySnapshot { telemetry },
        state,
        state_coordinates,
        history,
        history_limits: limits,
        retained_history,
        emitted_events,
        resource_limits,
    };
    if evaluator.checkpoint()?.bytes != checkpoint.bytes {
        return Err(SignalEvaluationError::NonCanonicalCheckpoint);
    }
    Ok(evaluator)
}
