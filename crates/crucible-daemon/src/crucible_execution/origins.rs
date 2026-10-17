//! Decoded selected-continuation ancestry that keeps one configuration resident.
//!
//! A continuation attempt replays every origin attempt from its base. Each
//! origin's reached configuration is a prefix of its successor's, so the whole
//! ancestry is a set of prefixes of the terminal origin's configuration:
//!
//! ```text
//! terminal reached: [d0 d1 d2 d3 d4 d5 d6 d7 d8]
//! origin 1:         [d0 d1 d2]                    -> TerminalPrefix(len 3)
//! origin 2:         [d0 d1 d2 d3 d4 d5]           -> TerminalPrefix(len 6)
//! ```
//!
//! [`CrucibleAttemptOrigins`] keeps the terminal origin decoded and every
//! earlier origin as its attempt, stop proof, and reached length. Iteration
//! materializes one earlier origin at a time: its configuration is the
//! terminal's prefix over shared decision storage, and its signal-fault replay
//! plan is the terminal plan restricted to branches inside that prefix.
//! Decoding admits that compact form only after the materialized origin equals
//! the independently decoded one; an origin that is not such a restriction is
//! kept decoded, so materialization never changes what consumers observe.

use super::*;

/// One decoded origin attempt and its claimed post-stop replay boundary.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct CrucibleAttemptOrigin {
    pub(super) attempt: Attempt,
    pub(super) reached: Configuration,
    pub(super) signal_fault_replay: SignalFaultCampaignReplayPlan,
    pub(super) source_stop: Option<StopOutcome>,
}

impl CrucibleAttemptOrigin {
    /// Binds one immutable origin attempt to its authenticated reached boundary.
    #[must_use]
    pub fn new(
        attempt: Attempt,
        reached: Configuration,
        signal_fault_replay: SignalFaultCampaignReplayPlan,
    ) -> Self {
        Self {
            attempt,
            reached,
            signal_fault_replay,
            source_stop: None,
        }
    }

    /// Binds a controlled origin to its authenticated final stop outcome.
    #[must_use]
    pub fn new_with_source_stop(
        attempt: Attempt,
        reached: Configuration,
        signal_fault_replay: SignalFaultCampaignReplayPlan,
        source_stop: StopOutcome,
    ) -> Self {
        Self {
            attempt,
            reached,
            signal_fault_replay,
            source_stop: Some(source_stop),
        }
    }

    /// Returns the immutable origin attempt whose stop is replayed.
    #[must_use]
    pub const fn attempt(&self) -> &Attempt {
        &self.attempt
    }

    /// Returns the exact configuration required at the origin stop.
    #[must_use]
    pub const fn reached(&self) -> &Configuration {
        &self.reached
    }

    /// Returns the promoted signal-fault replay plan for the reached boundary.
    #[must_use]
    pub const fn signal_fault_replay(&self) -> &SignalFaultCampaignReplayPlan {
        &self.signal_fault_replay
    }

    /// Returns the authenticated final stop outcome for controlled continuation.
    #[must_use]
    pub const fn source_stop(&self) -> Option<&StopOutcome> {
        self.source_stop.as_ref()
    }
}

/// Nonempty decoded ancestry for one selected continuation boundary.
///
/// Only the terminal origin is retained decoded; see the module
/// documentation for how earlier origins are materialized.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct CrucibleAttemptOrigins {
    earlier: Vec<OriginLink>,
    terminal: CrucibleAttemptOrigin,
}

/// One non-terminal origin, oldest first.
#[derive(Clone, Debug, PartialEq, Eq)]
pub(super) struct OriginLink {
    attempt: Attempt,
    source_stop: Option<StopOutcome>,
    boundary: OriginBoundary,
}

/// How a non-terminal origin's reached boundary and replay plan are retained.
#[derive(Clone, Debug, PartialEq, Eq)]
enum OriginBoundary {
    /// The terminal origin's boundary and plan restricted to this many
    /// decisions.
    TerminalPrefix(usize),
    /// The boundary and plan exactly as decoded.
    Decoded(Box<(Configuration, SignalFaultCampaignReplayPlan)>),
}

/// Error returned when an earlier origin no longer restricts its terminal.
///
/// Decoding admits a compact origin only after materializing it once, and
/// materialization is deterministic, so this indicates a broken invariant
/// rather than an input condition.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct CrucibleOriginMaterializationError;

impl std::fmt::Display for CrucibleOriginMaterializationError {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter.write_str("selected-continuation origin does not restrict its terminal origin")
    }
}

impl std::error::Error for CrucibleOriginMaterializationError {}

impl CrucibleAttemptOrigins {
    /// Binds one required origin and any later descendants.
    ///
    /// Every origin is retained exactly as given.
    #[must_use]
    pub fn new(first: CrucibleAttemptOrigin, mut rest: Vec<CrucibleAttemptOrigin>) -> Self {
        let Some(terminal) = rest.pop() else {
            return Self::from_terminal(first);
        };
        let earlier = std::iter::once(first)
            .chain(rest)
            .map(|origin| OriginLink {
                attempt: origin.attempt,
                source_stop: origin.source_stop,
                boundary: OriginBoundary::Decoded(Box::new((
                    origin.reached,
                    origin.signal_fault_replay,
                ))),
            })
            .collect();
        Self { earlier, terminal }
    }

    /// Starts an ancestry from its decoded terminal origin.
    pub(super) fn from_terminal(terminal: CrucibleAttemptOrigin) -> Self {
        Self {
            earlier: Vec::new(),
            terminal,
        }
    }

    /// Appends the next earlier origin, oldest first, in its smallest exact form.
    ///
    /// Returns `true` when the origin is retained as a terminal prefix and
    /// `false` when it is retained decoded.
    pub(super) fn push_earlier(&mut self, decoded: CrucibleAttemptOrigin) -> bool {
        let reached_len = decoded.reached.schedule.len();
        let restricted = restrict_terminal(
            &self.terminal,
            &decoded.attempt,
            reached_len,
            decoded.source_stop.as_ref(),
        );
        let compact = restricted.as_ref() == Ok(&decoded);
        let boundary = if compact {
            OriginBoundary::TerminalPrefix(reached_len)
        } else {
            OriginBoundary::Decoded(Box::new((decoded.reached, decoded.signal_fault_replay)))
        };
        self.earlier.push(OriginLink {
            attempt: decoded.attempt,
            source_stop: decoded.source_stop,
            boundary,
        });
        compact
    }

    /// Returns the final origin that establishes the semantic start boundary.
    #[must_use]
    pub const fn last(&self) -> &CrucibleAttemptOrigin {
        &self.terminal
    }

    /// Materializes each origin from the authenticated base toward the
    /// selected boundary, one at a time.
    ///
    /// An earlier origin's configuration shares the terminal's decision
    /// storage, so holding several materialized origins costs their chunk
    /// tables rather than their decisions.
    pub fn iter(
        &self,
    ) -> impl Iterator<Item = Result<CrucibleAttemptOrigin, CrucibleOriginMaterializationError>> + '_
    {
        self.earlier
            .iter()
            .map(|link| match &link.boundary {
                OriginBoundary::TerminalPrefix(reached_len) => restrict_terminal(
                    &self.terminal,
                    &link.attempt,
                    *reached_len,
                    link.source_stop.as_ref(),
                ),
                OriginBoundary::Decoded(boundary) => Ok(CrucibleAttemptOrigin {
                    attempt: link.attempt.clone(),
                    reached: boundary.0.clone(),
                    signal_fault_replay: boundary.1.clone(),
                    source_stop: link.source_stop.clone(),
                }),
            })
            .chain(std::iter::once(Ok(self.terminal.clone())))
    }

    /// Returns the number of decoded origin attempts.
    #[must_use]
    pub fn len(&self) -> usize {
        self.earlier.len() + 1
    }

    /// Returns false because a selected continuation always has an origin.
    #[must_use]
    pub const fn is_empty(&self) -> bool {
        false
    }
}

/// Rebuilds an earlier origin from the terminal's first `reached_len` decisions.
fn restrict_terminal(
    terminal: &CrucibleAttemptOrigin,
    attempt: &Attempt,
    reached_len: usize,
    source_stop: Option<&StopOutcome>,
) -> Result<CrucibleAttemptOrigin, CrucibleOriginMaterializationError> {
    let schedule = terminal
        .reached
        .schedule
        .prefix(reached_len)
        .map_err(|_| CrucibleOriginMaterializationError)?;
    let reached = Configuration {
        def: terminal.reached.def.clone(),
        schedule,
    };

    // Branches are recorded in schedule order, so those inside the prefix
    // are exactly the ones whose selected configuration fits within it.
    let plan = &terminal.signal_fault_replay;
    let branches = plan
        .branches()
        .iter()
        .filter(|branch| branch.selected().len() <= reached_len)
        .cloned()
        .collect();
    let network_branches = plan
        .network_branches()
        .iter()
        .filter(|branch| branch.selected().schedule.len() <= reached_len)
        .cloned()
        .collect();
    let signal_fault_replay = SignalFaultCampaignReplayPlan::new(reached.clone(), branches)
        .map_err(|_| CrucibleOriginMaterializationError)?
        .with_network_branches(network_branches)
        .map_err(|_| CrucibleOriginMaterializationError)?;

    Ok(CrucibleAttemptOrigin {
        attempt: attempt.clone(),
        reached,
        signal_fault_replay,
        source_stop: source_stop.cloned(),
    })
}

#[cfg(test)]
mod tests;
