//! Keeps the normal Root daemon's genuine startup capture on the shared substrate.
//!
//! These server-local owners remain nonauthorizing. The original PID1 image is
//! captured and retained in this process; no descriptor or self-report is
//! transferred to Controller.

pub use aos_sandbox::normal_root::{
    NormalRootStartupErrorV1, ProductionNormalRootStartupCaptureV1, ProductionNormalRootStartupV1,
};

pub(crate) fn recheck_optional(
    owner: Option<&ProductionNormalRootStartupV1>,
) -> Result<(), NormalRootStartupErrorV1> {
    if let Some(owner) = owner {
        owner.recheck()?;
    }
    Ok(())
}
