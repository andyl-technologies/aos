//! Startup recovery classifications used by the fixed protected owner.

/// Classifies legacy prior-process death evidence retained by older consumers.
///
/// New startup authority does not mint this caller-visible selector. Exact
/// current execution, launcher, boot, and terminal AOSMSA attempt provenance
/// are committed directly in `AOSMMCAP1`.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum MountManagerExecutionDeathKindV1 {
    /// The retained execution belonged to a replaced boot.
    BootReplaced,
    /// Its exact pidfd became exit-ready.
    PidfdExited,
    /// The numeric process identifier was reused.
    ProcessReplaced,
}
