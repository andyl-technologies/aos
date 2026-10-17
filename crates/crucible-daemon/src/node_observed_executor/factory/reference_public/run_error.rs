//! Preserves typed qualification failures across the owning actor boundary.
//!
//! These errors describe invocation, publication or evidence refusal. They do
//! not certify native cessation, replace retained failed-case observations, or
//! grant execution authority. Underlying diagnostics retain their original text.

use std::sync::mpsc;

use crucible_node_provider::ProviderError;

use crate::{node_observed_executor::NodeObservedError, node_qualification::QualificationError};

/// Reports installed-source, actor or evidence failure without granting trust.
#[derive(Debug, thiserror::Error)]
pub enum QualificationRunError {
    /// The compiled source installation could not authenticate its artifacts.
    #[error(transparent)]
    Installation(#[from] NodeObservedError),
    /// The actor could not reserve or create its operational resources.
    #[error(transparent)]
    Io(#[from] std::io::Error),
    /// The owning actor reported its original provider or evidence failure.
    #[error(transparent)]
    Actor(#[from] ProviderError),
    /// The result channel ended without an original completed actor result.
    #[error(transparent)]
    Channel(#[from] mpsc::RecvError),
    /// The concrete installed evidence gate rejected the original population.
    #[error(transparent)]
    Qualification(#[from] QualificationError),
    /// A required immutable scope or durable original result was unavailable.
    #[error("{0}")]
    Refused(&'static str),
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn typed_failures_preserve_original_diagnostic_text() {
        let provider = ProviderError::Correlation("original actor evidence differs");
        let provider_text = provider.to_string();
        assert_eq!(
            QualificationRunError::from(provider).to_string(),
            provider_text
        );

        let evidence = QualificationError::Refused("original review is unresolved");
        let evidence_text = evidence.to_string();
        assert_eq!(
            QualificationRunError::from(evidence).to_string(),
            evidence_text
        );

        let io = std::io::Error::new(std::io::ErrorKind::WouldBlock, "actor already reserved");
        let io_text = io.to_string();
        assert_eq!(QualificationRunError::from(io).to_string(), io_text);
        assert_eq!(
            QualificationRunError::Refused("scope changed").to_string(),
            "scope changed"
        );
    }

    #[test]
    fn channel_loss_remains_distinct_from_an_actor_failure() {
        let (sender, receiver) = mpsc::channel::<()>();
        drop(sender);
        let error = receiver.recv().err().map(QualificationRunError::from);
        assert!(matches!(error, Some(QualificationRunError::Channel(_))));
    }
}
