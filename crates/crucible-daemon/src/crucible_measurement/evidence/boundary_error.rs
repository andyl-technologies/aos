//! Original typed operational causes crossing the pure campaign codec boundary.

use std::error::Error;
use std::fmt;

use crucible::owned_decode::{DecodeAdmissionError, DecodeCustody};
use crucible_campaign::CampaignCodecError;

/// Admits a fixed shared cause envelope before validation can exhaust its bank.
pub(crate) fn admit<T>() -> Result<DecodeCustody, DecodeAdmissionError> {
    let custody = crucible::owned_decode::require_current_custody()?;
    // Rust object layouts are bounded by isize::MAX; adding two Arc words
    // remains representable in usize on the supported 64-bit host.
    let bytes = std::mem::size_of::<RetainedCause<T>>() + 2 * std::mem::size_of::<usize>();
    crucible::owned_decode::charge_bytes(bytes as u64)?;
    Ok(custody)
}

pub(crate) fn campaign<T>(source: T, custody: DecodeCustody) -> CampaignCodecError
where
    T: Error + Send + Sync + 'static,
{
    CampaignCodecError::DecodeAdmission(decode(source, custody))
}

pub(crate) fn decode<T>(source: T, custody: DecodeCustody) -> DecodeAdmissionError
where
    T: Error + Send + Sync + 'static,
{
    DecodeAdmissionError::new(RetainedCause {
        source,
        _custody: custody,
    })
}

#[derive(Debug)]
struct RetainedCause<T> {
    source: T,
    _custody: DecodeCustody,
}

impl<T: fmt::Display> fmt::Display for RetainedCause<T> {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        self.source.fmt(formatter)
    }
}

impl<T: Error + 'static> Error for RetainedCause<T> {
    fn source(&self) -> Option<&(dyn Error + 'static)> {
        Some(&self.source)
    }
}
