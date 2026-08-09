//! CLI error taxonomy, rendering, and exit-status mapping.

use super::*;

#[derive(Debug)]
pub(in super::super) enum CliError {
    Io(io::Error),
    Store(crucible::DagStoreError),
    Artifact(String),
    Usage(String),
    Serve(String),
    Backend(String),
    Identity(String),
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
            Self::Serve(_) => 3,
            Self::Backend(_) => 4,
            Self::Identity(_) => 3,
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
            Self::Backend(error) => write!(formatter, "{error}"),
            Self::Identity(error) => write!(formatter, "{error}"),
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
            Self::Backend(_) => None,
            Self::Identity(_) => None,
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
