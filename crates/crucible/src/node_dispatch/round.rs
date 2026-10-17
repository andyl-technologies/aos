//! Bounded disjoint-owner rounds and retained original completion obligations.

use std::{
    collections::BTreeMap,
    task::{Context, Poll},
};

use crucible_node_contract::{Id, MAX_ARRAY_ELEMENTS, Position};

use crate::{
    node_contract::{
        BeginResult, NodeRuntime, OperationOutcome, OperationToken, RuntimeError,
        RuntimePollFailure, Submission,
    },
    node_scheduling::{ExecutionAdmission, SchedulingCommit},
};

enum MemberState {
    Pending,
    Ready(Box<OperationOutcome>),
    Failed(String),
}

struct Member {
    token: OperationToken,
    state: MemberState,
    commit: Option<SchedulingCommit>,
    acknowledged: bool,
}

/// Identifies canonical publication order independently of native completion.
#[derive(Clone, Debug, PartialEq, Eq, PartialOrd, Ord)]
pub struct DispatchOrder {
    /// Gives the original authorized start coordinate.
    pub start: Position,
    /// Breaks independent-owner ties by logical ASCII node identity.
    pub node: Id,
    /// Breaks otherwise equal requests by original operation identity.
    pub operation: Id,
}

/// Retains the result of one deterministic round publication.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct RoundPublication {
    /// Lists original operations in canonical publication order.
    pub operations: Vec<Id>,
    /// Lists complete validated native outcomes in that same order.
    pub outcomes: Vec<OperationOutcome>,
}

/// Retains native custody and undispatched grants when round start fails.
pub struct DispatchStartFailure {
    /// Describes the admission refusal or uncertain native submission.
    pub reason: String,
    /// Retains every original token whose native effects may have begun.
    pub accepted: Vec<OperationToken>,
    /// Returns unused original grants without widening or reminting them.
    pub undispatched: Vec<ExecutionAdmission>,
}

impl std::fmt::Debug for DispatchStartFailure {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter
            .debug_struct("DispatchStartFailure")
            .field("reason", &self.reason)
            .field("accepted", &self.accepted)
            .field("undispatched", &self.undispatched)
            .finish()
    }
}

/// Owns one bounded native round while preserving original runtime custody.
///
/// Polling performs at most one poll per pending member and registers the
/// caller's waker with native adapters. No busy loop fabricates modeled progress.
/// Dropping this value leaves original runtime entries reserved and recoverable.
pub struct DispatchRound {
    order: Vec<DispatchOrder>,
    members: BTreeMap<Id, Member>,
    publication: Option<RoundPublication>,
}

impl DispatchRound {
    /// Preflights the full owner roster before starting any original request.
    ///
    /// # Errors
    /// Returns all unused grants on no-effect preflight failure. A refusal or
    /// uncertainty after some native submissions retains their original tokens;
    /// it never treats partial start as rollback or repeats an accepted request.
    pub fn start(
        runtime: &mut NodeRuntime,
        mut grants: Vec<ExecutionAdmission>,
        maximum_members: usize,
    ) -> Result<Self, DispatchStartFailure> {
        if maximum_members == 0
            || maximum_members > MAX_ARRAY_ELEMENTS
            || grants.is_empty()
            || grants.len() > maximum_members
        {
            return Err(DispatchStartFailure {
                reason: "round member capacity exceeded".into(),
                accepted: Vec::new(),
                undispatched: grants,
            });
        }
        grants.sort_by_key(|grant| DispatchOrder {
            start: grant.start(),
            node: grant.node().clone(),
            operation: grant.operation().clone(),
        });
        if let Err(error) = runtime.validate_admitted_batch(&grants) {
            return Err(DispatchStartFailure {
                reason: error.to_string(),
                accepted: Vec::new(),
                undispatched: grants,
            });
        }
        let order: Vec<_> = grants
            .iter()
            .map(|grant| DispatchOrder {
                start: grant.start(),
                node: grant.node().clone(),
                operation: grant.operation().clone(),
            })
            .collect();
        let mut members = BTreeMap::new();
        let mut iterator = grants.into_iter();
        while let Some(grant) = iterator.next() {
            let (reason, uncertain) = match runtime.begin_admitted(grant) {
                Ok(BeginResult::Accepted(token)) => {
                    members.insert(
                        token.operation().clone(),
                        Member {
                            token,
                            state: MemberState::Pending,
                            commit: None,
                            acknowledged: false,
                        },
                    );
                    continue;
                }
                Ok(BeginResult::Uncertain { token, effects }) => (
                    format!("uncertain native round submission: {effects:?}"),
                    Some(token),
                ),
                Ok(BeginResult::Refused(refusal)) => (refusal.reason, None),
                Err(error) => (error.to_string(), None),
            };
            let mut accepted: Vec<_> = members.into_values().map(|member| member.token).collect();
            if let Some(token) = uncertain {
                accepted.push(token);
            }
            return Err(DispatchStartFailure {
                reason,
                accepted,
                undispatched: iterator.collect(),
            });
        }
        Ok(Self {
            order,
            members,
            publication: None,
        })
    }

    /// Polls every pending member once while withholding incomplete publication.
    ///
    /// Ready results remain cached under their original operation. A later call
    /// does not repoll a terminal native result or dispatch a replacement run.
    ///
    /// # Errors
    /// Returns the first failure in canonical order only after polling all pending
    /// members. Every accepted native owner remains retained for containment.
    pub fn poll(
        &mut self,
        runtime: &mut NodeRuntime,
        context: &mut Context<'_>,
    ) -> Poll<Result<(), DispatchError>> {
        for member in self.members.values_mut() {
            if !matches!(member.state, MemberState::Pending) {
                continue;
            }
            match runtime.poll(&member.token, context) {
                Poll::Pending => {}
                Poll::Ready(Ok(outcome)) => member.state = MemberState::Ready(Box::new(outcome)),
                Poll::Ready(Err(error)) => member.state = MemberState::Failed(format!("{error:?}")),
            }
        }
        for order in &self.order {
            if let Some(Member {
                state: MemberState::Failed(reason),
                ..
            }) = self.members.get(&order.operation)
            {
                return Poll::Ready(Err(DispatchError::Native {
                    operation: order.operation.clone(),
                    reason: reason.clone(),
                }));
            }
        }
        if self
            .members
            .values()
            .any(|member| matches!(member.state, MemberState::Pending))
        {
            return Poll::Pending;
        }
        Poll::Ready(Ok(()))
    }

    /// Copies validated original outcomes before publication or native release.
    ///
    /// Outcomes retain canonical round order independently of host completion.
    /// Callers can retrieve immutable native evidence while original output
    /// custody remains retained; inspecting this copy performs no acknowledgement.
    ///
    /// # Errors
    /// Refuses incomplete rounds or a failed native member whose original custody
    /// still requires containment.
    pub fn ready_outcomes(&self) -> Result<Vec<OperationOutcome>, DispatchError> {
        let mut outcomes = Vec::with_capacity(self.order.len());
        for order in &self.order {
            match &self
                .members
                .get(&order.operation)
                .ok_or(DispatchError::UnknownOperation)?
                .state
            {
                MemberState::Ready(outcome) => outcomes.push((**outcome).clone()),
                MemberState::Pending => return Err(DispatchError::Incomplete),
                MemberState::Failed(reason) => {
                    return Err(DispatchError::Native {
                        operation: order.operation.clone(),
                        reason: reason.clone(),
                    });
                }
            }
        }
        Ok(outcomes)
    }

    /// Requests closure of one original quantized member without another run.
    ///
    /// # Errors
    /// Refuses unknown members or runtime-native closure errors. Uncertainty
    /// retains the same original token and every outstanding effect obligation.
    pub fn close_quantum(
        &mut self,
        runtime: &mut NodeRuntime,
        operation: &Id,
    ) -> Result<Submission, DispatchError> {
        let member = self
            .members
            .get(operation)
            .ok_or(DispatchError::UnknownOperation)?;
        runtime
            .close_quantum(&member.token)
            .map_err(DispatchError::Runtime)
    }

    /// Commits a complete validated round in its canonical original order.
    ///
    /// A native acknowledgement failure retains the minted commit for retry.
    /// Retry never republishes an already committed result. Every native result
    /// must be ready before the first coordinator commit is attempted.
    ///
    /// # Errors
    /// Refuses incomplete or failed rounds and preserves original commitments
    /// after scheduling or native acknowledgement failure.
    pub fn publish(
        &mut self,
        runtime: &mut NodeRuntime,
    ) -> Result<&RoundPublication, DispatchError> {
        if self
            .members
            .values()
            .any(|member| !matches!(member.state, MemberState::Ready(_)))
        {
            return Err(DispatchError::Incomplete);
        }
        let pending: Vec<_> = self
            .order
            .iter()
            .filter_map(|order| self.members.get(&order.operation))
            .filter(|member| member.commit.is_none())
            .map(|member| &member.token)
            .collect();
        runtime
            .preflight_scheduling_receipts(&pending)
            .map_err(DispatchError::Runtime)?;
        for order in &self.order {
            let member = self
                .members
                .get_mut(&order.operation)
                .ok_or(DispatchError::UnknownOperation)?;
            if member.acknowledged {
                continue;
            }
            if member.commit.is_none() {
                let receipt = runtime
                    .scheduling_receipt(&member.token)
                    .map_err(DispatchError::Runtime)?;
                let commit = runtime
                    .commit_scheduling_receipt(receipt)
                    .map_err(DispatchError::Runtime)?;
                member.commit = Some(commit);
            }
            let commit = member.commit.as_ref().ok_or(DispatchError::Incomplete)?;
            runtime
                .acknowledge_scheduled(&member.token, commit)
                .map_err(DispatchError::Poll)?;
            member.acknowledged = true;
        }
        if self.publication.is_none() {
            self.publication = Some(RoundPublication {
                operations: self
                    .order
                    .iter()
                    .map(|order| order.operation.clone())
                    .collect(),
                outcomes: self.ready_outcomes()?,
            });
        }
        self.publication.as_ref().ok_or(DispatchError::Incomplete)
    }

    /// Returns original member tokens for supervision and explicit containment.
    pub fn tokens(&self) -> impl Iterator<Item = &OperationToken> {
        self.order.iter().filter_map(|order| {
            self.members
                .get(&order.operation)
                .map(|member| &member.token)
        })
    }
}

/// Reports operational dispatch failure without producing application findings.
#[derive(Debug, thiserror::Error)]
pub enum DispatchError {
    /// A member identity is not part of this original round.
    #[error("unknown original round operation")]
    UnknownOperation,
    /// An unresolved member prevents any canonical round publication.
    #[error("round native outcomes are incomplete")]
    Incomplete,
    /// Runtime admission or closure refused the requested operation.
    #[error("runtime refused dispatch: {0}")]
    Runtime(#[from] RuntimeError),
    /// Native acknowledgement or custody validation failed.
    #[error("native custody acknowledgement failed: {0:?}")]
    Poll(RuntimePollFailure),
    /// A validated result could not yet be causally committed.
    #[error("coordinator publication refused: {0}")]
    Scheduling(String),
    /// A native member failed with original effects retained under supervision.
    #[error("native operation {operation} failed: {reason}")]
    Native {
        /// Names the original failed operation.
        operation: Id,
        /// Retains its classified native failure diagnostic.
        reason: String,
    },
}
