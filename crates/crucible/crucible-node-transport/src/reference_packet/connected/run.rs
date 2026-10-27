//! Separate actual reaction and next-microstep publication under original cuts.

use super::*;

#[derive(Serialize)]
#[serde(tag = "action", rename_all = "snake_case")]
enum NativeTrace<'a> {
    Delivery {
        delivery: &'a PacketDeliveredInput,
    },
    Reaction {
        operation: &'a Id,
        reaction: &'a PacketReaction,
    },
    Publication {
        publication: &'a PacketConnectedPublication,
    },
}

enum PlannedEffect {
    Delivery(PacketDeliveredInput),
    Reaction(PacketReaction, Option<PacketPendingPublication>),
    Publication(PacketConnectedPublication),
}

struct Plan {
    completed: PacketConnectedGrant,
    effects: Vec<(Vec<u8>, PlannedEffect)>,
}

impl PacketConnectedProgram {
    /// Borrows the same genuine original grant, including an incomplete attempt.
    pub fn original(&self, operation: &Id) -> Option<&PacketConnectedGrant> {
        self.grants.get(operation)
    }

    fn plan(
        &self,
        operation: &Id,
        start: Position,
        limit: Position,
    ) -> Result<Plan, ProviderError> {
        self.current()?;
        if self.gate_closed
            || start != self.reached
            || start > limit
            || limit.microstep.get() >= MAXIMUM_MICROSTEPS
            || self.grants.len() >= MAXIMUM_OPERATIONS
            || !self.outputs.is_empty()
            || self
                .stages
                .last()
                .is_none_or(|stage| stage.commit.is_none() || limit > stage.record.cut.cutoff)
        {
            return Err(ProviderError::Correlation(
                "packet phased grant has no original consumed cut",
            ));
        }
        let mut inventory = self.inventory()?;
        let mut effects = Vec::with_capacity(MAXIMUM_EVENTS * 3);
        let mut newborn = Vec::with_capacity(MAXIMUM_EVENTS);
        loop {
            let reaction = inventory.reactions.first().map(|reaction| {
                if inventory
                    .delivered_inputs
                    .iter()
                    .any(|delivery| delivery.reaction == *reaction)
                {
                    reaction.evaluation
                } else {
                    reaction.parent
                }
            });
            let publication = inventory
                .publications
                .first()
                .map(|publication| publication.publication);
            let next = match (reaction, publication) {
                (Some(a), Some(b)) => a.min(b),
                (Some(a), None) | (None, Some(a)) => a,
                (None, None) => break,
            };
            if next >= limit {
                break;
            }
            if publication == Some(next) {
                let pending = inventory.publications.remove(0);
                let sequence = inventory.packet_effects.checked_add(U64::new(1))?;
                let output = PacketConnectedPublication {
                    output: PacketPublication {
                        event: pending.event.clone(),
                        operation: operation.clone(),
                        sequence,
                        evaluation: pending.reaction.evaluation,
                        publication: pending.publication,
                        payload: pending.reaction.payload.clone(),
                    },
                    pending,
                };
                let trace = encode_trace(&NativeTrace::Publication {
                    publication: &output,
                })?;
                inventory.packet_effects = sequence;
                inventory.retained_outputs.push(output.clone());
                newborn.push(output.clone());
                effects.push((trace, PlannedEffect::Publication(output)));
            } else {
                let reaction = inventory.reactions.first().ok_or(ProviderError::Frame(
                    "packet original next input step absent",
                ))?;
                if next == reaction.parent {
                    let delivery = PacketDeliveredInput {
                        reaction: reaction.clone(),
                        delivery_operation: operation.clone(),
                    };
                    let trace = encode_trace(&NativeTrace::Delivery {
                        delivery: &delivery,
                    })?;
                    inventory.delivered_inputs.push(delivery.clone());
                    effects.push((trace, PlannedEffect::Delivery(delivery)));
                    continue;
                }
                let reaction = inventory.reactions.remove(0);
                let publication = if self.definition.output.is_some() {
                    Some(PacketPendingPublication {
                        event: Id::new(format!(
                            "packet-reaction-{}",
                            reaction.input_event.as_str()
                        ))?,
                        publication: reaction
                            .evaluation
                            .reaction_publication(U64::new(MAXIMUM_MICROSTEPS))?,
                        reaction: reaction.clone(),
                        reaction_operation: operation.clone(),
                    })
                } else {
                    None
                };
                if let Some(publication) = &publication {
                    inventory.publications.push(publication.clone());
                    inventory
                        .publications
                        .sort_by(|a, b| (a.publication, &a.event).cmp(&(b.publication, &b.event)));
                }
                inventory.reactions_completed =
                    inventory.reactions_completed.checked_add(U64::new(1))?;
                let trace = encode_trace(&NativeTrace::Reaction {
                    operation,
                    reaction: &reaction,
                })?;
                effects.push((trace, PlannedEffect::Reaction(reaction, publication)));
            }
        }
        inventory.reached = limit;
        let completed = PacketConnectedGrant {
            operation: operation.clone(),
            start,
            limit,
            inventory,
            newborn,
            complete: true,
        };
        crate::connection::serialized_credit(&completed, MAXIMUM_RECORD)?;
        Ok(Plan { completed, effects })
    }

    /// Plans complete bounded prospective effects without executing a native step.
    ///
    /// The result is credit data, not proof that any callback occurred.
    ///
    /// # Errors
    /// Refuses unavailable source ownership, changed cuts or uncommitted input.
    pub fn preview(
        &self,
        operation: &Id,
        start: Position,
        limit: Position,
    ) -> Result<PacketConnectedGrant, ProviderError> {
        self.current()?;
        if let Some(original) = self.grants.get(operation) {
            if original.start == start && original.limit == limit && original.complete {
                return Ok(original.clone());
            }
            return Err(ProviderError::Conflict("packet phased original preview"));
        }
        Ok(self.plan(operation, start, limit)?.completed)
    }

    /// Executes only native steps strictly below one complete original exclusive cut.
    ///
    /// A reaction may stop with a retained future publication. No packet is
    /// emitted until a later grant includes that actual Publication position.
    /// Every uncertain socket effect retains the same incomplete original and
    /// fences this originating process against replacement native execution.
    ///
    /// # Errors
    /// Refuses unavailable or changed original permission, source credit or I/O failure.
    pub fn run(
        &mut self,
        operation: Id,
        start: Position,
        limit: Position,
    ) -> Result<&PacketConnectedGrant, ProviderError> {
        self.current()?;
        if let Some(original) = self.grants.get(&operation) {
            if original.start == start && original.limit == limit && original.complete {
                return self
                    .grants
                    .get(&operation)
                    .ok_or(ProviderError::Frame("packet original phased grant absent"));
            }
            return Err(ProviderError::Conflict(
                "packet phased original attempt remains unknown",
            ));
        }
        let plan = self.plan(&operation, start, limit)?;
        self.grants.insert(
            operation.clone(),
            PacketConnectedGrant {
                operation: operation.clone(),
                start,
                limit,
                inventory: self.inventory()?,
                newborn: Vec::new(),
                complete: false,
            },
        );
        for (trace, effect) in plan.effects {
            match self.effect_socket.send(&trace) {
                Ok(length) if length == trace.len() => {}
                Ok(_) => {
                    self.failed = true;
                    return Err(ProviderError::Frame(
                        "packet native datagram effect incomplete",
                    ));
                }
                Err(error) => {
                    self.failed = true;
                    return Err(error.into());
                }
            }
            match effect {
                PlannedEffect::Delivery(delivery) => {
                    if self.reactions.first() != Some(&delivery.reaction)
                        || self
                            .delivered_inputs
                            .iter()
                            .any(|original| original.reaction == delivery.reaction)
                    {
                        self.failed = true;
                        return Err(ProviderError::Correlation(
                            "packet original delivery changed",
                        ));
                    }
                    self.reached = delivery.reaction.parent;
                    self.delivered_inputs.push(delivery);
                }
                PlannedEffect::Reaction(reaction, publication) => {
                    if self.reactions.first() != Some(&reaction) {
                        self.failed = true;
                        return Err(ProviderError::Correlation(
                            "packet original phased reaction changed",
                        ));
                    }
                    self.reactions.remove(0);
                    self.reactions_completed += 1;
                    self.reached = reaction.evaluation;
                    if let Some(publication) = publication {
                        self.publications.push(publication);
                        self.publications.sort_by(|a, b| {
                            (a.publication, &a.event).cmp(&(b.publication, &b.event))
                        });
                    }
                }
                PlannedEffect::Publication(output) => {
                    if self.publications.first() != Some(&output.pending) {
                        self.failed = true;
                        return Err(ProviderError::Correlation(
                            "packet original phased publication changed",
                        ));
                    }
                    self.publications.remove(0);
                    self.packet_effects += 1;
                    self.reached = output.output.publication;
                    self.outputs.push(output);
                }
            }
        }
        self.reached = plan.completed.inventory.reached;
        let retained = self.grants.get_mut(&operation).ok_or(ProviderError::Frame(
            "packet original phased reservation absent",
        ))?;
        *retained = plan.completed;
        self.grants
            .get(&operation)
            .ok_or(ProviderError::Frame("packet actual phased grant absent"))
    }

    /// Retires exactly one complete actual native output population once.
    ///
    /// # Errors
    /// Refuses changed original output IDs, incomplete grants or foreign custody.
    pub fn retire(&mut self, operation: &Id, events: &[Id]) -> Result<(), ProviderError> {
        self.current()?;
        if let Some(original) = self.retired.get(operation) {
            return if original == events {
                Ok(())
            } else {
                Err(ProviderError::Conflict(
                    "packet original phased retirement changed",
                ))
            };
        }
        let original = self
            .grants
            .get(operation)
            .filter(|grant| grant.complete)
            .ok_or(ProviderError::Correlation(
                "packet phased retirement has no complete original",
            ))?;
        let expected = original
            .newborn
            .iter()
            .map(|output| output.output.event.clone())
            .collect::<Vec<_>>();
        if events != expected
            || self
                .outputs
                .iter()
                .any(|output| &output.output.operation != operation)
        {
            return Err(ProviderError::Conflict(
                "packet complete phased output population changed",
            ));
        }
        self.retired.insert(operation.clone(), expected);
        self.outputs.clear();
        Ok(())
    }
}

fn encode_trace(trace: &NativeTrace<'_>) -> Result<Vec<u8>, ProviderError> {
    crate::connection::serialized_credit(trace, MAXIMUM_RECORD)?;
    Ok(canonical::canonical_json(
        &serde_json::to_value(trace).map_err(ContractError::from)?,
    )?)
}
