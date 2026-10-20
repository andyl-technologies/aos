//! Applies the original fixed Controller status DATA predicate.

use super::ControllerProfileErrorV1 as NormalRootStartupErrorV1;

/// Applies the exact capability and NoNewPrivs predicate to status DATA.
///
/// # Errors
/// Refuses invalid UTF-8, missing/duplicate fields or altered fixed values.
pub fn require_status(bytes: &[u8]) -> Result<(), NormalRootStartupErrorV1> {
    let text = std::str::from_utf8(bytes).map_err(|_| NormalRootStartupErrorV1::Confinement)?;
    for name in [
        "CapInh",
        "CapPrm",
        "CapEff",
        "CapBnd",
        "CapAmb",
        "NoNewPrivs",
    ] {
        let mut values = text
            .lines()
            .filter_map(|line| line.strip_prefix(&format!("{name}:")));
        let value = values
            .next()
            .ok_or(NormalRootStartupErrorV1::Confinement)?
            .trim();
        if values.next().is_some()
            || if name == "NoNewPrivs" {
                value != "1"
            } else {
                value.len() != 16 || !value.bytes().all(|byte| byte == b'0')
            }
        {
            return Err(NormalRootStartupErrorV1::Confinement);
        }
    }
    Ok(())
}

/// Refuses a retained fixed self-status read without replacing its native cause.
#[derive(Clone, Copy, Debug, thiserror::Error)]
#[error("current process status read is incomplete or refused")]
pub struct CurrentProcessStatusClosedV1;

/// Retains the same bounded thread-self status reader and every reached byte.
///
/// Status bytes are comparison DATA only. The actual role supplies its own
/// predicate, process association and payment; this owner selects no foreign
/// PID, path, account, credential or application authority.
#[must_use = "retain this entire native reader through the role's owed posts"]
pub struct CurrentProcessStatusOriginalV1 {
    original: super::shared_read::BoundedFileReadOriginalV1,
    result: Option<Result<(), CurrentProcessStatusClosedV1>>,
    entered: bool,
    reentered: bool,
    taken: bool,
    closed: CurrentProcessStatusClosedV1,
}

impl CurrentProcessStatusOriginalV1 {
    const MAXIMUM_BYTES: usize = 64 * 1024;

    /// Creates empty result destinations without IO or allocation.
    #[must_use]
    pub const fn new() -> Self {
        Self {
            original: super::shared_read::BoundedFileReadOriginalV1::new(),
            result: None,
            entered: false,
            reentered: false,
            taken: false,
            closed: CurrentProcessStatusClosedV1,
        }
    }

    /// Quotes the actual bounded native reader, input and fixed path.
    #[must_use]
    pub fn receiving_demand_v1() -> Option<aos_sandbox_core::ResourceVector> {
        use aos_sandbox_core::{ResourceDimension as D, ResourceVector};
        let memory = std::mem::size_of::<Self>().checked_mul(2)?
            .checked_add(super::shared_read::BoundedFileReadOriginalV1::requested_bytes_v1(
                Self::MAXIMUM_BYTES,
            )?)?;
        Some(ResourceVector::ZERO
            .with(D::MemoryBytes, u64::try_from(memory).ok()?)
            .with(D::OpenFiles, 1)
            .with(D::MetadataEntries, 4)
            .with(D::OutputBytes, u64::try_from(Self::MAXIMUM_BYTES.checked_add(1)?).ok()?))
    }

    /// Enters the existing fixed status reader once, retaining its actual file.
    ///
    /// # Errors
    /// Retains native open/read failure or excess bytes and refuses a second
    /// entry, including after an interrupted first read, without further IO.
    pub fn observe_once_v1(&mut self) -> Result<(), CurrentProcessStatusClosedV1> {
        if self.entered {
            self.reentered = true;
            return Err(self.closed);
        }
        self.entered = true;
        self.result = Some(self.original.read_once(
            "/proc/thread-self/status", Self::MAXIMUM_BYTES as u64, false, true,
        ).map_err(|_| self.closed).and_then(|()| {
            if self.original.bytes.len() <= Self::MAXIMUM_BYTES { Ok(()) } else { Err(self.closed) }
        }));
        if matches!(self.result, Some(Ok(()))) { Ok(()) } else { Err(self.closed) }
    }

    /// Borrows only the completed bounded status DATA without another read.
    #[must_use]
    pub fn bytes_v1(&self) -> Option<&[u8]> {
        if self.reentered || self.taken || !matches!(self.result, Some(Ok(()))) {
            return None;
        }
        Some(&self.original.bytes)
    }

    /// Moves positive bytes once while the native reader remains on this owner.
    ///
    /// This DATA-only handoff neither retires the file nor refunds its quote.
    #[must_use]
    pub fn take_completed_bytes_once_v1(&mut self) -> Option<Vec<u8>> {
        self.bytes_v1()?;
        self.taken = true;
        Some(std::mem::take(&mut self.original.bytes))
    }

    /// Borrows the first original native or closed-comparison failure.
    #[must_use]
    pub fn failure_v1(&self) -> Option<&(dyn std::error::Error + 'static)> {
        self.original.failure()
            .or_else(|| self.result.as_ref()?.as_ref().err().map(|cause| cause as _))
            .or_else(|| self.reentered.then_some(&self.closed as &dyn std::error::Error))
    }
}
