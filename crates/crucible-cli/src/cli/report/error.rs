//! CLI error taxonomy, rendering, and exit-status mapping.

use super::*;

#[derive(Debug)]
pub(in super::super) enum CliError {
    Io(io::Error),
    Store(crucible::DagStoreError),
    Artifact(String),
    Usage(String),
    Serve(String),
    SqliteStartup(crucible_daemon::campaign_store_composition::StoreError),
    Backend(String),
    Identity(String),
    EventEvidence {
        context: &'static str,
        source: Box<crucible::EngineError>,
    },
    MetadataAdmission(crucible_session::engine::owned_decode::DecodeAdmissionError),
    LifecycleAdmission(Box<crucible_api::LifecycleApiError>),
    InputAuthority(Box<crucible_daemon::campaign_store_composition::StoreError>),
    ProviderAdmission(crucible_daemon::ProviderServiceAdmissionError),
    CampaignArchive(crucible_campaign::CampaignRepositoryError),
    ArchiveTransfer(crucible_daemon::CampaignArchiveTransferError),
    ExecutionAdmission {
        context: &'static str,
        source: NativeExecutionAdmissionError,
    },
    SaveWorkflowTrace {
        source: Box<CliError>,
        trace: SaveWorkflowFailureTrace,
    },
    Outcome(BackendCommandStatus),
    ReplayCheck(String),
    InvalidScenario(String),
    Triage(String),
    #[cfg(any(test, feature = "test-double"))]
    Selftest(crucible::ExampleCorpusError),
}

impl CliError {
    pub(in super::super) fn exit_code(&self) -> i32 {
        match self {
            Self::Io(_) => 5,
            Self::Store(_) => 5,
            Self::Artifact(_) => 5,
            Self::Usage(_) => 64,
            Self::Serve(_) | Self::SqliteStartup(_) => 3,
            Self::Backend(_) => 4,
            Self::Identity(_) => 3,
            Self::EventEvidence { .. } => 4,
            Self::MetadataAdmission(_) => 4,
            Self::InputAuthority(_) | Self::LifecycleAdmission(_) | Self::ProviderAdmission(_) => 4,
            Self::CampaignArchive(_) | Self::ArchiveTransfer(_) => 4,
            Self::ExecutionAdmission { .. } => 4,
            Self::SaveWorkflowTrace { source, .. } => source.exit_code(),
            Self::Outcome(BackendCommandStatus::Passed) => 0,
            Self::Outcome(BackendCommandStatus::Failed) => 1,
            Self::Outcome(BackendCommandStatus::Timeout) => 2,
            Self::Outcome(BackendCommandStatus::Crashed) => 3,
            Self::ReplayCheck(_) => 1,
            Self::InvalidScenario(_) => 5,
            Self::Triage(_) => 1,
            #[cfg(any(test, feature = "test-double"))]
            Self::Selftest(_) => 1,
        }
    }
}

impl fmt::Display for CliError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Io(error) => write!(formatter, "{error}"),
            Self::Store(error) => write!(formatter, "{error}"),
            Self::Artifact(error) => write!(formatter, "{error}"),
            Self::Usage(error) => write!(formatter, "{error}"),
            Self::Serve(error) => write!(formatter, "{error}"),
            Self::SqliteStartup(error) => write!(formatter, "SQLite process admission: {error}"),
            Self::Backend(error) => write!(formatter, "{error}"),
            Self::Identity(error) => write!(formatter, "{error}"),
            Self::EventEvidence { context, source } => write!(formatter, "{context}: {source}"),
            Self::MetadataAdmission(source) => {
                write!(formatter, "input metadata admission: {source}")
            }
            Self::LifecycleAdmission(source) => write!(formatter, "lifecycle admission: {source}"),
            Self::InputAuthority(source) => write!(formatter, "input resource authority: {source}"),
            Self::ProviderAdmission(source) => {
                write!(formatter, "input resource authority: {source}")
            }
            Self::CampaignArchive(source) => write!(formatter, "archive operation: {source}"),
            Self::ArchiveTransfer(source) => write!(formatter, "archive transfer: {source}"),
            Self::ExecutionAdmission { context, source } => {
                write!(formatter, "{context}: {source}")
            }
            Self::SaveWorkflowTrace { source, .. } => write!(formatter, "{source}"),
            Self::Outcome(status) => write!(formatter, "run ended with {status:?}"),
            Self::ReplayCheck(error) => write!(formatter, "{error}"),
            Self::InvalidScenario(error) => write!(formatter, "{error}"),
            Self::Triage(error) => write!(formatter, "{error}"),
            #[cfg(any(test, feature = "test-double"))]
            Self::Selftest(error) => write!(formatter, "selftest failed: {error}"),
        }
    }
}

impl Error for CliError {
    fn source(&self) -> Option<&(dyn Error + 'static)> {
        match self {
            Self::Io(error) => Some(error),
            Self::Store(error) => Some(error),
            Self::Artifact(_) => None,
            Self::Usage(_) => None,
            Self::Serve(_) => None,
            Self::SqliteStartup(source) => Some(source),
            Self::Backend(_) => None,
            Self::Identity(_) => None,
            Self::EventEvidence { source, .. } => Some(source.as_ref()),
            Self::MetadataAdmission(source) => Some(source),
            Self::LifecycleAdmission(source) => Some(source.as_ref()),
            Self::InputAuthority(source) => Some(source.as_ref()),
            Self::ProviderAdmission(source) => Some(source),
            Self::CampaignArchive(source) => Some(source),
            Self::ArchiveTransfer(source) => Some(source),
            Self::ExecutionAdmission { source, .. } => Some(source),
            Self::SaveWorkflowTrace { source, .. } => Some(source.as_ref()),
            Self::Outcome(_) => None,
            Self::ReplayCheck(_) => None,
            Self::InvalidScenario(_) => None,
            Self::Triage(_) => None,
            #[cfg(any(test, feature = "test-double"))]
            Self::Selftest(error) => Some(error),
        }
    }
}

impl From<io::Error> for CliError {
    fn from(error: io::Error) -> Self {
        Self::Io(error)
    }
}

pub(in super::super) fn usage_error(reason: impl Into<String>) -> CliError {
    CliError::Usage(reason.into())
}

pub(in super::super) fn serve_error(reason: impl Into<String>) -> CliError {
    CliError::Serve(reason.into())
}

pub(in super::super) fn backend_error(reason: impl Into<String>) -> CliError {
    CliError::Backend(reason.into())
}
