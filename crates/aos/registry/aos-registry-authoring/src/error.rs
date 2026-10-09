//! Registry authoring errors presented by the APR dispatcher.

/// Describes a registry operation rejected by the producer dispatcher.
#[derive(Debug, thiserror::Error)]
pub enum RegistryAuthoringError {
    /// Reports an invalid registry operation.
    #[error("registry error: {message}")]
    RegistryError { message: String },
}
