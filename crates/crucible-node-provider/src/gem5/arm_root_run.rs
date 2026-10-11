//! Exact serial prefix execution with original failed-Poll and ACK custody.
//!
//! A native refusal establishes zero callbacks for this subordinate Poll only.
//! Earlier successful prefixes remain retained and cannot become effect-free.

use crucible_node_contract::U64;
use serde_json::json;

use super::{
    ArmRootExactAuthority, ArmRootNativeProcess, ArmRootPrefix, ArmRootRunOutcome, Gem5Run,
};
use crate::ProviderError;

impl ArmRootNativeProcess {
    /// Executes or retries one original exact native prefix under current authority.
    ///
    /// Original raw frames remain retained before any data interpretation or ACK.
    ///
    /// # Errors
    /// Refuses foreign authority, changed original scope, held output, exhausted
    /// host credits, uncertain transport, native overshoot or invalid birth data.
    pub fn run_exact(
        &mut self,
        authority: &ArmRootExactAuthority,
        original: Gem5Run,
    ) -> Result<ArmRootRunOutcome, ProviderError> {
        authority.require_live(self)?;
        if let Some(outcome) = self.completed.get(&original.operation) {
            if outcome.original() != &original {
                return Err(ProviderError::Conflict(
                    "ARM retry changes original native permission",
                ));
            }
            return Ok(outcome.clone());
        }
        if self.pending.is_some()
            || self.unresolved.is_some()
            || self.unresolved_capture.is_some()
            || original.kind != "run"
            || original.maximum_events.get() == 0
            || original.maximum_events.get() > 1_000_000
            || original
                .exact_range
                .as_ref()
                .is_none_or(|range| range.maximum_microsteps != authority.maximum_microsteps())
        {
            return Err(ProviderError::Conflict(
                "ARM original prefix custody or policy differs",
            ));
        }
        let range = original
            .exact_range
            .as_ref()
            .ok_or(ProviderError::Frame("ARM exact range omitted"))?;
        if range.start != self.boundary.logical_position
            || range.start >= range.limit
            || range.maximum_microsteps.get() < 2
            || range.start.microstep >= range.maximum_microsteps
            || range.limit.microstep >= range.maximum_microsteps
            || original.exclusive_tick != range.limit.time_ps
        {
            return Err(ProviderError::Correlation(
                "ARM full-range permission differs from current cut",
            ));
        }
        if self.completed.len() >= 512 {
            return Err(ProviderError::ResourceExhausted(
                "ARM retained original prefix allowance",
            ));
        }
        let request = serde_json::to_value(&original)
            .map_err(|_| ProviderError::Frame("ARM prefix encoding"))?;
        self.unresolved = Some(request.clone());
        let response = self.exchange(request)?;
        let bytes = self
            .custody
            .as_ref()
            .and_then(|custody| custody.control_frames.last())
            .ok_or(ProviderError::Frame(
                "ARM original native response not retained",
            ))?
            .clone();
        let outcome = if response.get("kind") == Some(&json!("run_refused")) {
            let parsed = super::refusal::parse_run_refusal_for_model(
                &bytes,
                "crucible.gem5.arm-linux-native/1",
                super::model::Gem5ModelDialect::ArmLinux,
                &self.ready.diagnostic_credit_policy,
                &original,
                &self.boundary,
            )?;
            ArmRootRunOutcome::Refused {
                refusal: parsed.receipt().clone(),
                bytes,
            }
        } else {
            let prefix: ArmRootPrefix = serde_json::from_value(response)
                .map_err(|_| ProviderError::Frame("ARM typed serial prefix shape"))?;
            validate(&prefix, &original, &self.boundary, self.last_serial_id())?;
            self.boundary = prefix.after.clone();
            ArmRootRunOutcome::Completed { prefix, bytes }
        };
        self.completed
            .insert(original.operation.clone(), outcome.clone());
        self.pending = Some(original.operation);
        self.unresolved = None;
        Ok(outcome)
    }

    /// Acknowledges original successful output only after caller publication custody.
    ///
    /// # Errors
    /// Refuses absent, refused or foreign pending custody and uncertain native ACK.
    pub fn acknowledge(
        &mut self,
        operation: &crucible_node_contract::Id,
    ) -> Result<(), ProviderError> {
        self.ack_original(operation, false)
    }

    /// Acknowledges failed-Poll administration without completing output or a grant.
    ///
    /// # Errors
    /// Refuses successful or foreign prefix custody and uncertain native ACK.
    pub fn acknowledge_refusal(
        &mut self,
        operation: &crucible_node_contract::Id,
    ) -> Result<(), ProviderError> {
        self.ack_original(operation, true)
    }

    fn ack_original(
        &mut self,
        operation: &crucible_node_contract::Id,
        refused: bool,
    ) -> Result<(), ProviderError> {
        if self.unresolved.is_some()
            || self.unresolved_capture.is_some()
            || (self.pending.as_ref() != Some(operation)
                && self.last_acknowledged.as_ref() != Some(operation))
        {
            return Err(ProviderError::Conflict("ARM original ACK custody differs"));
        }
        let outcome = self
            .completed
            .get(operation)
            .ok_or(ProviderError::Frame("ARM ACK original omitted"))?;
        if refused != matches!(outcome, ArmRootRunOutcome::Refused { .. }) {
            return Err(ProviderError::Correlation(
                "ARM successful/refused ACK class differs",
            ));
        }
        let request =
            json!({"kind":if refused {"ack_refused"} else {"acknowledge"},"operation":operation});
        self.unresolved = Some(request.clone());
        let response = self.exchange(request)?;
        if response
            != json!({"kind":if refused {"refusal_acknowledged"} else {"acknowledged"},"operation":operation})
        {
            return Err(ProviderError::Correlation(
                "ARM original native ACK receipt differs",
            ));
        }
        self.pending = None;
        self.last_acknowledged = Some(operation.clone());
        self.unresolved = None;
        Ok(())
    }

    fn last_serial_id(&self) -> U64 {
        self.completed
            .values()
            .filter_map(ArmRootRunOutcome::completion)
            .flat_map(|prefix| &prefix.publications)
            .map(|publication| publication.output_id)
            .max()
            .unwrap_or(U64::new(0))
    }
}

pub(crate) fn validate(
    prefix: &ArmRootPrefix,
    original: &Gem5Run,
    before: &super::Gem5Boundary,
    last_output: U64,
) -> Result<(), ProviderError> {
    let range = original
        .exact_range
        .as_ref()
        .ok_or(ProviderError::Frame("ARM exact range absent"))?;
    if prefix.kind != "completed"
        || prefix.operation != original.operation
        || prefix.original != *original
        || prefix.before != *before
        || prefix.processed_events > original.maximum_events
        || prefix.after.ordinal.get().checked_sub(before.ordinal.get())
            != Some(prefix.processed_events.get())
        || prefix.after.tick < before.tick
        || prefix.after.logical_position < range.start
        || prefix.after.logical_position > range.limit
        || prefix.output.len() > 4 * 1024 * 1024
        || prefix.publications.len() > 4 * 1024 * 1024
        || prefix.output
            != prefix
                .publications
                .iter()
                .flat_map(|body| body.payload.iter().copied())
                .collect::<Vec<_>>()
    {
        return Err(ProviderError::Correlation(
            "ARM exact original prefix progress differs",
        ));
    }
    if matches!(prefix.reason.as_str(), "horizon" | "idle") {
        if prefix.after.logical_position != range.limit
            || prefix
                .after
                .next_reaction(range.maximum_microsteps)?
                .is_some_and(|next| next < range.limit)
        {
            return Err(ProviderError::Correlation(
                "ARM horizon lacks native callback exclusion",
            ));
        }
    } else if !matches!(
        prefix.reason.as_str(),
        "output" | "event_budget" | "guest_exit"
    ) || prefix.processed_events.get() == 0
    {
        return Err(ProviderError::Correlation(
            "ARM completion lacks actual native progress",
        ));
    }
    if prefix.processed_events.get() > 0 {
        let reaction = callback(
            prefix.after.tick,
            prefix.after.tick_ordinal,
            range.maximum_microsteps,
        )?;
        if reaction < range.start
            || reaction >= range.limit
            || reaction >= prefix.after.logical_position
        {
            return Err(ProviderError::Correlation(
                "ARM serviced callback outruns original full range",
            ));
        }
    }
    let mut output_id = last_output.get();
    for publication in &prefix.publications {
        output_id = output_id
            .checked_add(1)
            .ok_or(ProviderError::Frame("ARM original serial ID exhausted"))?;
        publication.validate_birth(before, &prefix.after, output_id.into(), 0.into())?;
        let reaction = callback(
            publication.tick,
            publication.tick_ordinal,
            range.maximum_microsteps,
        )?;
        if reaction < range.start || reaction >= range.limit {
            return Err(ProviderError::Correlation(
                "ARM serial birth outruns original interval",
            ));
        }
    }
    if (prefix.reason == "output" && prefix.publications.is_empty())
        || (!prefix.publications.is_empty()
            && !matches!(prefix.reason.as_str(), "output" | "guest_exit"))
    {
        return Err(ProviderError::Correlation(
            "ARM completion reason differs from held serial FIFO",
        ));
    }
    Ok(())
}

fn callback(
    tick: U64,
    tie: U64,
    cap: U64,
) -> Result<crucible_node_contract::Position, ProviderError> {
    let microstep = tie
        .get()
        .checked_sub(1)
        .and_then(|value| value.checked_mul(2))
        .filter(|value| {
            value
                .checked_add(1)
                .is_some_and(|publication| publication < cap.get())
        })
        .ok_or(ProviderError::ResourceExhausted(
            "ARM callback closure coordinate",
        ))?;
    Ok(crucible_node_contract::Position::new(
        tick,
        microstep.into(),
        crucible_node_contract::Phase::Reaction,
    ))
}

#[cfg(test)]
// crucible-lint: allow rust-allow -- invalid test fixtures must fail assertions.
// crucible-lint: allow panic-shortcut -- fixture construction and counterexample assertions are test-only.
#[allow(clippy::unwrap_used)]
mod tests {
    use super::*;
    use crucible_node_contract::{Id, Phase, Position};

    fn boundary(tick: u64, ordinal: u64, microstep: u64) -> super::super::Gem5Boundary {
        super::super::Gem5Boundary {
            tick: tick.into(),
            logical_position: Position::new(tick.into(), microstep.into(), Phase::BoundaryControl),
            ordinal: ordinal.into(),
            tick_ordinal: 1.into(),
            has_next_event: true,
            next_tick: (tick + 1).into(),
            next_priority: 0,
            inventory: json!({"complete":false}),
        }
    }

    fn prefix() -> ArmRootPrefix {
        let before = boundary(0, 0, 0);
        let after = boundary(10, 1, 1);
        ArmRootPrefix {
            kind: "completed".to_owned(),
            operation: Id::new("original").unwrap(),
            original: Gem5Run {
                kind: "run".to_owned(),
                operation: Id::new("original").unwrap(),
                exclusive_tick: 100.into(),
                maximum_events: 1.into(),
                exact_range: Some(super::super::Gem5ExactRange {
                    start: before.logical_position,
                    limit: Position::new(100.into(), 0.into(), Phase::BoundaryControl),
                    maximum_microsteps: 100.into(),
                }),
            },
            before,
            after,
            processed_events: 1.into(),
            reason: "output".to_owned(),
            output: vec![91],
            publications: vec![super::super::Gem5SerialPublication {
                facet: "serial".to_owned(),
                terminal: "system.terminal".to_owned(),
                output_id: 1.into(),
                tick: 10.into(),
                event_ordinal: 1.into(),
                tick_ordinal: 1.into(),
                causal_parent: 0.into(),
                payload: vec![91],
            }],
            exit_cause: None,
            exit_code: None,
        }
    }

    #[test]
    fn real_shape_serial_is_not_stdout_and_checks_original_birth() {
        let valid = prefix();
        validate(&valid, &valid.original, &valid.before, 0.into()).unwrap();
        let mut encoded = serde_json::to_value(&valid).unwrap();
        encoded["publications"][0]["guest_fd"] = json!(1);
        assert!(serde_json::from_value::<ArmRootPrefix>(encoded).is_err());
    }

    #[test]
    fn altered_original_parent_fifo_or_payload_is_rejected() {
        for change in 0..5 {
            let valid = prefix();
            let mut forged = valid.clone();
            match change {
                0 => forged.publications[0].causal_parent = 17.into(),
                1 => forged.publications[0].output_id = 2.into(),
                2 => forged.publications[0].event_ordinal = 2.into(),
                3 => forged.publications[0].tick_ordinal = 2.into(),
                _ => forged.output = vec![92],
            }
            assert!(validate(&forged, &valid.original, &valid.before, 0.into()).is_err());
        }
    }

    #[test]
    fn callback_or_horizon_must_not_escape_original_full_coordinate() {
        let valid = prefix();
        let mut forged = valid.clone();
        forged.original.exact_range.as_mut().unwrap().limit =
            Position::new(10.into(), 0.into(), Phase::Reaction);
        forged.original.exclusive_tick = 10.into();
        assert!(validate(&forged, &forged.original, &forged.before, 0.into()).is_err());
        forged = valid.clone();
        forged.reason = "horizon".to_owned();
        assert!(validate(&forged, &valid.original, &valid.before, 0.into()).is_err());
    }

    #[test]
    fn progress_and_budget_are_native_counters_not_host_elapsed_time() {
        let valid = prefix();
        let mut forged = valid.clone();
        forged.processed_events = 2.into();
        assert!(validate(&forged, &valid.original, &valid.before, 0.into()).is_err());
        forged = valid.clone();
        forged.after.ordinal = 0.into();
        assert!(validate(&forged, &valid.original, &valid.before, 0.into()).is_err());
    }

    #[test]
    fn required_null_exit_fields_and_clock_cap_are_closed() {
        let valid = prefix();
        let mut encoded = serde_json::to_value(&valid).unwrap();
        encoded.as_object_mut().unwrap().remove("exit_code");
        assert!(serde_json::from_value::<ArmRootPrefix>(encoded).is_err());
        assert!(callback(0.into(), 0.into(), 100.into()).is_err());
        assert!(callback(0.into(), u64::MAX.into(), 100.into()).is_err());
    }
}
