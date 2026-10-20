//! Fixed self-profile classification shared below Domain's Root owner.
//!
//! Native/serde causes stay on their actual retained receiving owners. These
//! five projections contain no caller-selected policy or authority claim.

/// Classifies a refused original Controller self-profile observation.
#[derive(Clone, Copy, Debug, Eq, PartialEq, thiserror::Error)]
pub enum ControllerProfileErrorV1 {
    /// Initial fixed descriptor delivery is absent or malformed.
    #[error("Controller original fixed delivery differs")]
    Activation,
    /// Selected profile shape, identity or unit commitment differs.
    #[error("Controller immutable profile differs")]
    Profile,
    /// Actual retained image, loader mapping or current name differs.
    #[error("Controller actual immutable image differs")]
    Image,
    /// Actual PID1 unit, invocation, process or cgroup observation differs.
    #[error("Controller actual fixed-unit custody differs")]
    Service,
    /// Enforcing subject, capabilities or canonical policy differs.
    #[error("Controller actual confinement differs")]
    Confinement,
}
