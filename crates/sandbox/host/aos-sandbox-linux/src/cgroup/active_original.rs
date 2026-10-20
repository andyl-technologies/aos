//! Retains the ordinary held-anchor active-reference probe without authority.

use super::*;

/// Owns one exact active-file probe and its original native refusal.
#[derive(Debug, Default)]
pub struct CgroupActiveOriginalV2 {
    pending: PendingRegularFileV1,
    returned: Option<Result<()>>,
    closed: Option<Error>,
    retired: Option<crate::path::FileIdentity>,
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn an_unentered_observation_has_no_positive_retirement() {
        let mut original = CgroupActiveOriginalV2::new();

        assert!(original.retire_positive_file_once_v2().is_err());

        assert!(original.retired.is_none());
        assert!(original.returned.is_none());
        assert!(original.pending.file().is_err());
    }
}

impl CgroupActiveOriginalV2 {
    /// Constructs inert inline native destinations.
    #[must_use]
    pub fn new() -> Self { Self::default() }

    /// Runs the sole existing held-anchor active-reference recipe once.
    ///
    /// # Errors
    /// Retains the native prefix and fences repeated entry without replacement.
    pub fn capture_once_v2(&mut self, anchor: &RetainedCgroupAnchor) -> Result<()> {
        if self.returned.is_some() || self.closed.is_some() {
            self.closed.get_or_insert_with(retained_native::closed);
            return Err(retained_native::closed());
        }
        self.returned = Some(anchor.validate_active_retaining(&mut self.pending));
        if matches!(self.returned, Some(Ok(()))) { Ok(()) }
        else { Err(retained_native::closed()) }
    }

    /// Borrows the first actual native or permanent refusal.
    #[must_use]
    pub fn failure(&self) -> Option<&Error> {
        self.returned.as_ref().and_then(|result| result.as_ref().err()).or(self.closed.as_ref())
    }

    /// Closes only this complete positive active-file observation once.
    ///
    /// The native result, file identity and entry fence remain resident. This
    /// physical disposal grants no currentness or financial capacity.
    ///
    /// # Errors
    /// Refuses failed, partial or already retired observations before closing.
    pub fn retire_positive_file_once_v2(&mut self) -> Result<()> {
        if self.retired.is_some() || self.closed.is_some()
            || !matches!(self.returned, Some(Ok(()))) {
            return Err(retained_native::closed());
        }
        let identity = self.pending.file()?.identity();
        drop(self.pending.take_readable_file());
        self.retired = Some(identity);
        Ok(())
    }

    /// Prices the actual native owner, probe descriptor and one fixed name.
    #[must_use]
    pub fn receiving_obligations_v2() -> Option<(usize, usize, usize)> {
        Some((std::mem::size_of::<Self>().checked_mul(2)?
            .checked_add(2 * b"cgroup.procs\0".len())?.checked_add(4 * 256)?, 1, 1))
    }
}
