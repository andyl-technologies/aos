//! Keeps the actual signing result beside both independent native posts.
//!
//! The selected Source observation retains this concrete typed destination
//! through its actual response. Ordinary callers use the same engine with a
//! temporary destination and preserve their original first-error projection.

use super::SourceSignerReadbackErrorV1;

pub(crate) struct SourceReadonlySigningPostsV1<T> {
    // This order matches disposal of the former ordinary locals: watermark,
    // physical names, then the returned result. No drop is proof of admission.
    pub(super) watermark: Option<Result<(), SourceSignerReadbackErrorV1>>,
    pub(super) names: Option<Result<(), SourceSignerReadbackErrorV1>>,
    pub(super) returned: Option<Result<T, SourceSignerReadbackErrorV1>>,
    entered: bool,
    refusal: Option<SourceSignerReadbackErrorV1>,
}

impl<T> SourceReadonlySigningPostsV1<T> {
    pub(crate) const fn new() -> Self {
        Self {
            watermark: None,
            names: None,
            returned: None,
            entered: false,
            refusal: None,
        }
    }

    pub(super) fn enter_once(&mut self) -> bool {
        if self.entered {
            self.refusal.get_or_insert(SourceSignerReadbackErrorV1::Stale);
            return false;
        }
        self.entered = true;
        true
    }

    /// Borrows the earliest actual result without discarding later post debt.
    pub(crate) fn failure(&self) -> Option<&SourceSignerReadbackErrorV1> {
        self.returned.as_ref().and_then(|result| result.as_ref().err())
            .or_else(|| self.names.as_ref().and_then(|result| result.as_ref().err()))
            .or_else(|| self.watermark.as_ref().and_then(|result| result.as_ref().err()))
            .or(self.refusal.as_ref())
    }

    /// Borrows packet DATA only after all three original results succeeded.
    pub(crate) fn packet(&self) -> Option<&T> {
        if self.refusal.is_some()
            || !matches!(self.names, Some(Ok(())))
            || !matches!(self.watermark, Some(Ok(())))
        {
            return None;
        }
        self.returned.as_ref()?.as_ref().ok()
    }

    // Only the ordinary temporary adapter moves the original projection. A
    // selected owner keeps every field until its actual final response posts.
    pub(super) fn take_ordinary(mut self) -> Result<T, SourceSignerReadbackErrorV1> {
        match self.returned.take().ok_or(SourceSignerReadbackErrorV1::Stale)? {
            Err(error) => Err(error),
            Ok(packet) => {
                self.names.take().ok_or(SourceSignerReadbackErrorV1::Stale)??;
                self.watermark.take().ok_or(SourceSignerReadbackErrorV1::Stale)?
                    .map(|()| packet)
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn primary_and_independent_negative_posts_remain_distinct_and_resident() {
        let mut capture = SourceReadonlySigningPostsV1::<()>::new();
        assert!(capture.enter_once());
        capture.returned = Some(Err(SourceSignerReadbackErrorV1::View));
        capture.names = Some(Err(SourceSignerReadbackErrorV1::Stale));
        capture.watermark = Some(Err(SourceSignerReadbackErrorV1::Journal(
            super::super::JournalError::ProtectedBoundary,
        )));

        assert!(matches!(capture.failure(), Some(SourceSignerReadbackErrorV1::View)));
        assert!(matches!(capture.names, Some(Err(SourceSignerReadbackErrorV1::Stale))));
        assert!(matches!(capture.watermark, Some(Err(SourceSignerReadbackErrorV1::Journal(_)))));
        assert!(capture.packet().is_none());

        assert!(!capture.enter_once());
        assert!(matches!(capture.failure(), Some(SourceSignerReadbackErrorV1::View)));
        assert!(matches!(capture.names, Some(Err(SourceSignerReadbackErrorV1::Stale))));
    }
}
