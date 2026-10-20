//! Retains a fixed nonce and every reached result of the same entropy walker.
//!
//! The sixteen-byte output and finite result array exist before native entry.
//! This mechanical owner supplies random DATA only: it admits no work and
//! creates no authorization, clock, financial account or role proof.

use std::error::Error;

use super::{EntropyError, EntropySource, KernelEntropy, fill_nonzero,
    MAXIMUM_ALL_ZERO_RETRIES, MAXIMUM_INTERRUPTED_RETRIES};
use rustix::io::Errno;

// A fill completes in at most sixteen positive one-byte calls plus eight
// interruptions. Nine all-zero fills are possible. A terminal ninth interrupt
// replaces a still-needed positive call, so it fits the same bound.
const MAXIMUM_CALLS: usize = (MAXIMUM_ALL_ZERO_RETRIES + 1) * (16 + MAXIMUM_INTERRUPTED_RETRIES);

/// Retains one fixed kernel nonce, partial bytes and all reached native results.
#[must_use]
pub struct RetainedKernelNonceOriginalV1 {
    bytes: [u8; 16],
    observations: [Option<Result<usize, Errno>>; MAXIMUM_CALLS],
    reached: usize,
    result: Option<Result<(), EntropyError>>,
    reentry: Option<EntropyError>,
}

impl Default for RetainedKernelNonceOriginalV1 {
    fn default() -> Self { Self::new() }
}

impl RetainedKernelNonceOriginalV1 {
    /// Constructs empty fixed custody without native work or allocation.
    #[must_use]
    pub const fn new() -> Self {
        Self {
            bytes: [0; 16], observations: [None; MAXIMUM_CALLS], reached: 0,
            result: None, reentry: None,
        }
    }

    /// Returns the fixed resident, construction and disposition byte bound.
    #[must_use]
    pub fn construction_bytes_v1() -> Option<usize> {
        std::mem::size_of::<Self>().checked_mul(3)
    }

    /// Samples once through the unchanged bounded kernel entropy algorithm.
    ///
    /// # Errors
    /// Preserves partial bytes and native errno on refusal; rejects reentry,
    /// zero progress and exhaustion exactly as the ordinary bounded walker.
    pub fn observe_once(&mut self) -> Result<[u8; 16], EntropyError> {
        self.observe_with_source(&mut KernelEntropy)
    }

    fn observe_with_source(&mut self, source: &mut impl EntropySource)
        -> Result<[u8; 16], EntropyError>
    {
        if self.result.is_some() {
            self.reentry.get_or_insert(EntropyError);
            return Err(EntropyError);
        }
        let mut retained = RetainingSource {
            source, observations: &mut self.observations, reached: &mut self.reached,
        };
        self.result = Some(fill_nonzero(&mut retained, &mut self.bytes));
        match self.result {
            Some(Ok(())) => Ok(self.bytes),
            _ => Err(EntropyError),
        }
    }

    /// Borrows only a completed nonzero result, with no reentry or refusal.
    #[must_use]
    pub fn value(&self) -> Option<&[u8; 16]> {
        if matches!(self.result, Some(Ok(()))) && self.reentry.is_none() {
            Some(&self.bytes)
        } else {
            None
        }
    }

    /// Borrows the terminal raw errno or the algorithm's exact refusal class.
    ///
    /// Earlier recovered interruptions remain resident but do not replace a
    /// later zero-progress/all-zero refusal or a successful complete fill.
    #[must_use]
    pub fn failure(&self) -> Option<&(dyn Error + 'static)> {
        if let Some(Err(cause)) = &self.result {
            return self.reached.checked_sub(1)
                .and_then(|index| self.observations.get(index))
                .and_then(Option::as_ref).and_then(|result| result.as_ref().err())
                .map(|cause| cause as &(dyn Error + 'static))
                .or(Some(cause as &(dyn Error + 'static)));
        }
        self.reentry.as_ref().map(|cause| cause as &(dyn Error + 'static))
    }
}

struct RetainingSource<'original, 'source, S> {
    source: &'source mut S,
    observations: &'original mut [Option<Result<usize, Errno>>; MAXIMUM_CALLS],
    reached: &'original mut usize,
}

impl<S: EntropySource> EntropySource for RetainingSource<'_, '_, S> {
    fn fill_once(&mut self, output: &mut [u8]) -> Result<usize, Errno> {
        let Some(destination) = self.observations.get_mut(*self.reached) else {
            // The ordinary walker reaches at most MAXIMUM_CALLS. Refuse before
            // any extra native work if that bound changes without this owner.
            return Err(Errno::OVERFLOW);
        };
        let result = self.source.fill_once(output);
        *destination = Some(result);
        *self.reached += 1;
        result
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    struct PartialThenFailure { calls: usize }

    impl EntropySource for PartialThenFailure {
        fn fill_once(&mut self, output: &mut [u8]) -> Result<usize, Errno> {
            self.calls += 1;
            match self.calls {
                1 => { output[..3].copy_from_slice(&[1, 2, 3]); Ok(3) }
                2 => Err(Errno::INTR),
                _ => Err(Errno::IO),
            }
        }
    }

    #[test]
    fn failed_fill_preserves_partial_bytes_and_terminal_native_errno() {
        let mut original = RetainedKernelNonceOriginalV1::new();
        let mut source = PartialThenFailure { calls: 0 };

        assert_eq!(original.observe_with_source(&mut source), Err(EntropyError));

        assert_eq!(&original.bytes[..3], &[1, 2, 3]);
        assert_eq!(original.reached, 3);
        assert_eq!(original.observations[1], Some(Err(Errno::INTR)));
        assert_eq!(original.observations[2], Some(Err(Errno::IO)));
        assert_eq!(original.failure().map(ToString::to_string), Some(Errno::IO.to_string()));
        assert!(original.value().is_none());
        assert_eq!(original.observe_with_source(&mut source), Err(EntropyError));
        assert_eq!(source.calls, 3);
        assert_eq!(&original.bytes[..3], &[1, 2, 3]);
    }
}
