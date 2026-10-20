//! Configured upload routing for Worker-fronted Native deployments.
//!
//! This policy selects the client transport before uploading. Provider errors
//! never change it, and neither mode permits bulk request bodies at Native.

/// Selects how clients send upload bytes in a hybrid deployment.
#[derive(Clone, Copy, Debug, Default, Eq, PartialEq)]
pub enum HybridUploadMode {
    /// Requires signed provider URLs and refuses unavailable direct controls.
    #[default]
    Direct,
    /// Explicitly uses the Worker's upload endpoints for storage bindings.
    WorkerProxy,
}

impl std::str::FromStr for HybridUploadMode {
    type Err = &'static str;

    /// Parses the deployment setting `direct` or `worker_proxy`.
    ///
    /// # Errors
    /// Returns an error for an unknown or noncanonical mode.
    fn from_str(value: &str) -> Result<Self, Self::Err> {
        match value {
            "direct" => Ok(Self::Direct),
            "worker_proxy" => Ok(Self::WorkerProxy),
            _ => Err("hybrid upload mode must be direct or worker_proxy"),
        }
    }
}
