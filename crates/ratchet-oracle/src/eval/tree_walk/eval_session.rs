//! Per-evaluation session plumbing: IFD realizer installation, call-depth
//! guarding, and the impure-aware search-path view.

use super::*;

impl TreeWalk {
    /// Installs the callback used to realize derivation outputs for IFD.
    pub fn set_ifd_realizer(&mut self, realizer: IfdRealizer) {
        self.ifd_realizer = Some(realizer);
    }

    /// Clears any configured IFD realizer.
    pub fn clear_ifd_realizer(&mut self) {
        self.ifd_realizer = None;
    }

    #[cfg(test)]
    pub(super) fn capture_stderr(&mut self) {
        self.stderr.capture();
    }

    #[cfg(test)]
    pub(super) fn captured_stderr(&self) -> &[u8] {
        self.stderr.captured()
    }

    #[cfg(test)]
    pub(super) fn import_parse_cache_stats(&self) -> (usize, usize) {
        (self.import_parse_cache_hits, self.import_parse_cache_misses)
    }

    pub(super) fn check_call_depth(&self, id: IrId, span: Span) -> Result<(), TreeWalkError> {
        let max = self.options.max_call_depth();
        if self.call_depth > max {
            return Err(TreeWalkError::new(
                TreeWalkErrorKind::MaxCallDepthExceeded {
                    id,
                    depth: self.call_depth,
                    max,
                },
                span,
            ));
        }
        Ok(())
    }

    pub(super) fn enter_call(&mut self, id: IrId, span: Span) -> Result<(), TreeWalkError> {
        self.check_call_depth(id, span)?;
        self.call_depth = self.call_depth.saturating_add(1);
        Ok(())
    }

    pub(super) fn leave_call(&mut self) {
        self.call_depth = self.call_depth.saturating_sub(1);
    }

    pub(super) fn visible_nix_path(&self) -> &[NixSearchPathEntry] {
        if self.options.eval_mode() == EvalMode::Pure {
            &[]
        } else {
            self.options.nix_path()
        }
    }
}
