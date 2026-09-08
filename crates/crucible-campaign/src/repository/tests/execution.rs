//! Attempt admission, observation, executor, and projection repository tests.

use super::*;
use crate::{
    CampaignRecordKind, CancelAttemptExecutionDisposition, CancelAttemptExecutionRequest,
    CancelAttemptExecutionResponse, CheckpointAttemptExecutionDisposition,
    CheckpointAttemptExecutionRequest, CheckpointAttemptExecutionResponse, ExactCheckpointId,
    ExecutorClient, ExecutorControlService, ExecutorResumeService, ExecutorService,
    ExecutorStatusService, Finding, FindingCandidateBundle, FindingExactPins, FindingKind,
    FindingMinimizationAttempt, FindingMinimizationEvidence, FindingOccurrenceSet,
    FindingSignature, FindingSignatureMinimizationEvidence, FindingTarget,
    GetAttemptExecutionDisposition, GetAttemptExecutionRequest, GetAttemptExecutionResponse,
    Objective, ObjectiveGoal, ObjectiveValue, ResumeAttemptExecutionDisposition,
    ResumeAttemptExecutionRequest, ResumeAttemptExecutionResponse, SelectionOrigin,
    evaluate_objectives,
};

struct CompletingExecutor {
    requests: Vec<SubmitAttemptRequest>,
    status_requests: Vec<GetAttemptExecutionRequest>,
    execution: ExecutionId,
    observation: ObservationId,
}

impl ExecutorService for CompletingExecutor {
    type Error = &'static str;

    fn submit_attempt(
        &mut self,
        request: &SubmitAttemptRequest,
    ) -> Result<SubmitAttemptResponse, Self::Error> {
        self.requests.push(request.clone());
        let disposition = SubmitAttemptDisposition::Accepted {
            execution: self.execution,
        };
        SubmitAttemptResponse::new(request, disposition).map_err(|_| "response encoding")
    }
}

impl ExecutorStatusService for CompletingExecutor {
    fn get_attempt_execution(
        &mut self,
        request: &GetAttemptExecutionRequest,
    ) -> Result<GetAttemptExecutionResponse, Self::Error> {
        self.status_requests.push(request.clone());
        GetAttemptExecutionResponse::new(
            request,
            GetAttemptExecutionDisposition::Completed {
                observation: self.observation,
            },
        )
        .map_err(|_| "response encoding")
    }
}

impl ExecutorResumeService for CompletingExecutor {
    fn resume_attempt_execution(
        &mut self,
        request: &ResumeAttemptExecutionRequest,
    ) -> Result<ResumeAttemptExecutionResponse, Self::Error> {
        ResumeAttemptExecutionResponse::new(request, ResumeAttemptExecutionDisposition::NotCurrent)
            .map_err(|_| "response encoding")
    }
}

struct TerminalExecutor {
    requests: Vec<SubmitAttemptRequest>,
    status_requests: Vec<GetAttemptExecutionRequest>,
    execution: ExecutionId,
}

impl ExecutorService for TerminalExecutor {
    type Error = &'static str;

    fn submit_attempt(
        &mut self,
        request: &SubmitAttemptRequest,
    ) -> Result<SubmitAttemptResponse, Self::Error> {
        self.requests.push(request.clone());
        SubmitAttemptResponse::new(
            request,
            SubmitAttemptDisposition::Accepted {
                execution: self.execution,
            },
        )
        .map_err(|_| "response encoding")
    }
}

impl ExecutorStatusService for TerminalExecutor {
    fn get_attempt_execution(
        &mut self,
        request: &GetAttemptExecutionRequest,
    ) -> Result<GetAttemptExecutionResponse, Self::Error> {
        self.status_requests.push(request.clone());
        GetAttemptExecutionResponse::new(request, GetAttemptExecutionDisposition::TerminalFailure)
            .map_err(|_| "response encoding")
    }
}

impl ExecutorResumeService for TerminalExecutor {
    fn resume_attempt_execution(
        &mut self,
        request: &ResumeAttemptExecutionRequest,
    ) -> Result<ResumeAttemptExecutionResponse, Self::Error> {
        ResumeAttemptExecutionResponse::new(request, ResumeAttemptExecutionDisposition::NotCurrent)
            .map_err(|_| "response encoding")
    }
}

struct RejectingExecutor {
    reason: ExecutorRejection,
}

struct DeferringExecutor {
    requests: Vec<SubmitAttemptRequest>,
}

impl ExecutorService for DeferringExecutor {
    type Error = &'static str;

    fn submit_attempt(
        &mut self,
        request: &SubmitAttemptRequest,
    ) -> Result<SubmitAttemptResponse, Self::Error> {
        self.requests.push(request.clone());
        SubmitAttemptResponse::new(
            request,
            SubmitAttemptDisposition::Rejected {
                reason: ExecutorRejection::Backpressure,
            },
        )
        .map_err(|_| "response encoding")
    }
}

impl ExecutorStatusService for DeferringExecutor {
    fn get_attempt_execution(
        &mut self,
        request: &GetAttemptExecutionRequest,
    ) -> Result<GetAttemptExecutionResponse, Self::Error> {
        GetAttemptExecutionResponse::new(request, GetAttemptExecutionDisposition::NotCurrent)
            .map_err(|_| "response encoding")
    }
}

impl ExecutorResumeService for DeferringExecutor {
    fn resume_attempt_execution(
        &mut self,
        request: &ResumeAttemptExecutionRequest,
    ) -> Result<ResumeAttemptExecutionResponse, Self::Error> {
        ResumeAttemptExecutionResponse::new(request, ResumeAttemptExecutionDisposition::NotCurrent)
            .map_err(|_| "response encoding")
    }
}

impl ExecutorService for RejectingExecutor {
    type Error = &'static str;

    fn submit_attempt(
        &mut self,
        request: &SubmitAttemptRequest,
    ) -> Result<SubmitAttemptResponse, Self::Error> {
        SubmitAttemptResponse::new(
            request,
            SubmitAttemptDisposition::Rejected {
                reason: self.reason,
            },
        )
        .map_err(|_| "response encoding")
    }
}

impl ExecutorStatusService for RejectingExecutor {
    fn get_attempt_execution(
        &mut self,
        request: &GetAttemptExecutionRequest,
    ) -> Result<GetAttemptExecutionResponse, Self::Error> {
        GetAttemptExecutionResponse::new(request, GetAttemptExecutionDisposition::NotCurrent)
            .map_err(|_| "response encoding")
    }
}

impl ExecutorResumeService for RejectingExecutor {
    fn resume_attempt_execution(
        &mut self,
        request: &ResumeAttemptExecutionRequest,
    ) -> Result<ResumeAttemptExecutionResponse, Self::Error> {
        ResumeAttemptExecutionResponse::new(
            request,
            ResumeAttemptExecutionDisposition::Rejected {
                reason: self.reason,
            },
        )
        .map_err(|_| "response encoding")
    }
}

struct CancellableExecutor {
    execution: ExecutionId,
    cancel_requests: Vec<CancelAttemptExecutionRequest>,
}

struct PausedResumeExecutor {
    prior_execution: ExecutionId,
    checkpoint: ExactCheckpointId,
    resumed_execution: ExecutionId,
    submit_requests: Vec<SubmitAttemptRequest>,
    resume_requests: Vec<ResumeAttemptExecutionRequest>,
}

impl ExecutorService for PausedResumeExecutor {
    type Error = &'static str;

    fn submit_attempt(
        &mut self,
        request: &SubmitAttemptRequest,
    ) -> Result<SubmitAttemptResponse, Self::Error> {
        self.submit_requests.push(request.clone());
        SubmitAttemptResponse::new(
            request,
            SubmitAttemptDisposition::AlreadyPaused {
                execution: self.prior_execution,
                checkpoint: self.checkpoint,
            },
        )
        .map_err(|_| "response encoding")
    }
}

impl ExecutorStatusService for PausedResumeExecutor {
    fn get_attempt_execution(
        &mut self,
        request: &GetAttemptExecutionRequest,
    ) -> Result<GetAttemptExecutionResponse, Self::Error> {
        GetAttemptExecutionResponse::new(request, GetAttemptExecutionDisposition::Running)
            .map_err(|_| "response encoding")
    }
}

impl ExecutorResumeService for PausedResumeExecutor {
    fn resume_attempt_execution(
        &mut self,
        request: &ResumeAttemptExecutionRequest,
    ) -> Result<ResumeAttemptExecutionResponse, Self::Error> {
        self.resume_requests.push(request.clone());
        ResumeAttemptExecutionResponse::new(
            request,
            ResumeAttemptExecutionDisposition::Accepted {
                execution: self.resumed_execution,
            },
        )
        .map_err(|_| "response encoding")
    }
}

impl ExecutorService for CancellableExecutor {
    type Error = &'static str;

    fn submit_attempt(
        &mut self,
        request: &SubmitAttemptRequest,
    ) -> Result<SubmitAttemptResponse, Self::Error> {
        SubmitAttemptResponse::new(
            request,
            SubmitAttemptDisposition::Accepted {
                execution: self.execution,
            },
        )
        .map_err(|_| "response encoding")
    }
}

impl ExecutorStatusService for CancellableExecutor {
    fn get_attempt_execution(
        &mut self,
        request: &GetAttemptExecutionRequest,
    ) -> Result<GetAttemptExecutionResponse, Self::Error> {
        GetAttemptExecutionResponse::new(request, GetAttemptExecutionDisposition::Running)
            .map_err(|_| "response encoding")
    }
}

impl ExecutorControlService for CancellableExecutor {
    fn checkpoint_attempt_execution(
        &mut self,
        request: &CheckpointAttemptExecutionRequest,
    ) -> Result<CheckpointAttemptExecutionResponse, Self::Error> {
        CheckpointAttemptExecutionResponse::new(
            request,
            CheckpointAttemptExecutionDisposition::NotCurrent,
        )
        .map_err(|_| "response encoding")
    }

    fn cancel_attempt_execution(
        &mut self,
        request: &CancelAttemptExecutionRequest,
    ) -> Result<CancelAttemptExecutionResponse, Self::Error> {
        self.cancel_requests.push(request.clone());
        CancelAttemptExecutionResponse::new(request, CancelAttemptExecutionDisposition::Canceled)
            .map_err(|_| "response encoding")
    }
}

impl ExecutorResumeService for CancellableExecutor {
    fn resume_attempt_execution(
        &mut self,
        request: &ResumeAttemptExecutionRequest,
    ) -> Result<ResumeAttemptExecutionResponse, Self::Error> {
        ResumeAttemptExecutionResponse::new(request, ResumeAttemptExecutionDisposition::NotCurrent)
            .map_err(|_| "response encoding")
    }
}

mod admission;
mod driver;
mod expansion;
mod publication;
mod validation;
