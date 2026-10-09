//! Registry authoring errors presented by the APR dispatcher.

#[derive(Debug, thiserror::Error)]
pub enum RegistryAuthoringError {
 /// Reports invalid registry command arguments.
 #[error("{message}")] InvalidArgument { message: String },
 /// Reports an invalid registry operation.
 #[error("{message}")] RegistryError { message: String },
 /// Reports a cancelled operation.
 #[error("operation cancelled")] UserCancelled,
}
