//! Persistent active-environment capture and installation.

use super::*;

impl TreeWalk {
    /// Captures the active persistent head, retaining the compatibility-array
    /// fallback for independently constructed test or restore frames.
    pub(super) fn capture_active_env_snapshot(
        &self,
        id: IrId,
        span: Span,
    ) -> Result<EvalEnv, TreeWalkError> {
        if let Some((head, frames)) = self.env.linked_parts() {
            return EvalEnv::capture_linked_head_with_flat_base(
                head.cloned(),
                frames,
                self.flat_env.clone(),
            )
            .map_err(|source| TreeWalkError::new(TreeWalkErrorKind::Env { id, source }, span));
        }
        EvalEnv::capture_with_flat_base(&self.env.to_vec(), self.flat_env.clone())
            .map_err(|source| TreeWalkError::new(TreeWalkErrorKind::Env { id, source }, span))
    }

    /// Installs a captured environment as a persistent active frame head.
    pub(in crate::eval::tree_walk) fn clone_env_frames(
        &self,
        id: IrId,
        env: &EvalEnv,
        span: Span,
    ) -> Result<ActiveEvalEnv, TreeWalkError> {
        let frames = env.frames();
        if self.options.eval_stats_dump() {
            crate::eval::env::note_env_install(frames.last());
        }
        if crate::eval::env::depth_probe_enabled() {
            crate::eval::env::note_install_depth(frames.len());
        }
        if frames.is_empty() {
            return Ok(ActiveEvalEnv {
                frames: ActiveEvalFrames::new(),
                flat_base: env.flat_base().cloned(),
            });
        }
        if let Some((head, frame_count)) = env.linked_parts() {
            return Ok(ActiveEvalEnv {
                frames: ActiveEvalFrames::from_linked(head.cloned(), frame_count),
                flat_base: env.flat_base().cloned(),
            });
        }
        let mut cloned = Vec::new();
        cloned.try_reserve_exact(frames.len()).map_err(|_| {
            TreeWalkError::new(
                TreeWalkErrorKind::Env {
                    id,
                    source: EvalEnvError::CaptureAllocationFailed {
                        frames: frames.len(),
                    },
                },
                span,
            )
        })?;
        frames.clone_into(&mut cloned);
        Ok(ActiveEvalEnv {
            frames: ActiveEvalFrames::from_vec(cloned),
            flat_base: env.flat_base().cloned(),
        })
    }
}
