//! Retains the actual healthy stat/context recipe on its existing source OFDs.
//!
//! Optional destinations change where native results reside. Ordinary callers
//! keep the same short-circuit order and lexical disposition. These receivers
//! select no path, process, phase, role, account or observation maximum.

use std::error::Error as StdError;

use super::*;
use super::identity_readback::{IdentityOriginalsV1, StatCaptureOriginalsV1};

pub(super) struct InfoOriginalV1 {
    info: Option<Result<PidFdInfo>>,
    binding: Option<Result<()>>,
    alive: Option<Result<bool>>,
    liveness: Option<Result<()>>,
}

impl InfoOriginalV1 {
    fn new() -> Self {
        Self { info: None, binding: None, alive: None, liveness: None }
    }

    pub(super) fn observe_healthy(&mut self, process: &PidFd, expected: Option<PidFdInfo>)
        -> Result<PidFdInfo>
    {
        self.info = Some(process.info());
        let info = match self.info.as_ref() { Some(Ok(info)) => *info, _ => return Err(closed()) };
        self.binding = Some(require_original_info_binding(info, expected));
        identity_readback::unit(&self.binding)?;
        self.alive = Some(process.is_alive());
        self.liveness = Some(match self.alive {
            Some(Ok(alive)) => require_original_liveness(alive),
            _ => Err(closed()),
        });
        identity_readback::unit(&self.liveness)?;
        Ok(info)
    }

    fn failure(&self) -> Option<&(dyn StdError + 'static)> {
        error(&self.info).or_else(|| error(&self.binding))
            .or_else(|| error(&self.alive)).or_else(|| error(&self.liveness))
    }
}

/// Retains one reached healthy proc observation and every original raw result.
///
/// The actual source continues to own its native File. This passive destination
/// cannot create that source, renew its phase or substitute another descriptor.
#[must_use = "keep this sink beside the same source through all owed posts"]
pub struct PidFdProcOriginalsV1 {
    identity: IdentityOriginalsV1,
    pub(super) context: StatCaptureOriginalsV1,
    pub(super) info: [InfoOriginalV1; 2],
    identity_result: Option<Result<PidFdProcessIdentity>>,
    context_result: Option<Result<()>>,
    entered: bool,
    reentry: Option<Error>,
}

impl PidFdProcOriginalsV1 {
    /// Creates inert original destinations without native IO.
    #[must_use]
    pub fn new() -> Self {
        Self {
            identity: IdentityOriginalsV1::new(), context: StatCaptureOriginalsV1::new(),
            info: std::array::from_fn(|_| InfoOriginalV1::new()),
            identity_result: None, context_result: None, entered: false, reentry: None,
        }
    }

    /// Supplies compiled carriers, bounded buffers and decoder work as bytes.
    ///
    /// The source owner separately retains/pays its actual stat/context Files.
    /// These native/result carriers create no resident namespace entries.
    #[must_use]
    pub fn receiving_bytes_v1() -> Option<usize> {
        let (stat, _) = PidFdProcObservationsV1::stat_receiving_footprint_v1();
        std::mem::size_of::<Self>().checked_mul(2)?.checked_add(stat)?
            .checked_add((CONTEXT_BYTES + 1).checked_mul(4)?)?
            .checked_add(2 * 64 + 8 * 256)
    }

    /// Supplies the common stat reader's maximum requested traffic with EOF.
    ///
    /// Healthy and prearmed negative observations use the same bounded native
    /// reader. This passive bound grants no read or healthy continuation.
    #[must_use]
    pub fn stat_maximum_requested_read_bytes_v1() -> Option<usize> {
        PidFdNegativeIdentityOriginalV1::maximum_requested_read_bytes_v1()
    }

    /// Supplies the common context reader's maximum requested traffic with EOF.
    ///
    /// This shares the actual context recipe's bound without selecting a role,
    /// descriptor, process, account or observation phase.
    #[must_use]
    pub fn context_maximum_requested_read_bytes_v1() -> Option<usize> {
        PidFdNegativeContextOriginalV1::maximum_requested_read_bytes_v1()
    }

    /// Borrows the earliest reached actual raw or typed cause without IO.
    #[must_use]
    pub fn failure(&self) -> Option<&(dyn StdError + 'static)> {
        if self.identity_result.is_some() {
            self.identity.failure().or_else(|| error(&self.identity_result))
        } else {
            self.info[0].failure().or_else(|| self.context.failure())
                .or_else(|| self.info[1].failure()).or_else(|| error(&self.context_result))
        }.or_else(|| self.reentry.as_ref().map(|cause| cause as _))
    }

    fn enter_once(&mut self) -> Result<()> {
        if self.entered {
            self.reentry.get_or_insert_with(closed);
            return Err(closed());
        }
        self.entered = true;
        Ok(())
    }

    fn identity_result(&self) -> Result<PidFdProcessIdentity> {
        self.identity_result.as_ref().and_then(|result| result.as_ref().ok()).copied()
            .ok_or_else(closed)
    }

    fn require_context_result(&self) -> Result<()> {
        if matches!(self.context_result, Some(Ok(()))) { Ok(()) } else { Err(closed()) }
    }
}

impl Default for PidFdProcOriginalsV1 {
    fn default() -> Self { Self::new() }
}

impl PidFdProcObservationsV1 {
    /// Captures stat through the same healthy recipe into its paid destination.
    ///
    /// # Errors
    /// Retains native acquisition/parser refusal and closes healthy readiness
    /// exactly as the ordinary recipe; reentry does not replace its first cause.
    pub fn capture_stat_retaining_v1(&mut self, process: &PidFd, original: &mut PidFdProcOriginalsV1)
        -> Result<PidFdProcessIdentity>
    {
        if original.enter_once().is_err() { self.fence(); return Err(closed()); }
        original.identity_result = Some((|| {
            let operation = self.begin(ObservationPhaseV1::Fresh)?;
            let result = operation.observations.capture_stat_inner_observed(process, Some(&mut original.identity));
            operation.finish(result, ObservationPhaseV1::StatCaptured)
        })());
        original.identity_result()
    }

    /// Captures context through the same healthy source and native recipe.
    ///
    /// # Errors
    /// Retains original info/open/filesystem/read/binding failure. Its source
    /// stays closed on refusal and keeps the actual reached descriptor.
    pub fn capture_context_retaining_v1(&mut self, process: &PidFd, original: &mut PidFdProcOriginalsV1)
        -> Result<&[u8]>
    {
        if original.enter_once().is_err() { self.fence(); return Err(closed()); }
        original.context_result = Some((|| {
            let operation = self.begin(ObservationPhaseV1::StatCaptured)?;
            let result = operation.observations.capture_context_inner_observed(process, Some(original));
            operation.finish(result, ObservationPhaseV1::Ready)
        })());
        original.require_context_result()?;
        Ok(&self.context.current)
    }

    /// Rereads the same stat OFD through the existing healthy identity recipe.
    ///
    /// # Errors
    /// Retains native, parser, binding or closed-source refusal without reopening.
    pub fn observe_identity_retaining_v1(&mut self, process: &PidFd, original: &mut PidFdProcOriginalsV1)
        -> Result<PidFdProcessIdentity>
    {
        if original.enter_once().is_err() { self.fence(); return Err(closed()); }
        original.identity_result = Some((|| {
            let operation = self.begin(ObservationPhaseV1::Ready)?;
            let result = (|| {
                let identity = operation.observations.reread_identity_inner_observed(process, Some(&mut original.identity))?;
                if Some(identity) != operation.observations.original_identity {
                    return Err(Error::invalid("proc observation", "original process identity changed"));
                }
                Ok(identity)
            })();
            operation.finish(result, ObservationPhaseV1::Ready)
        })());
        original.identity_result()
    }

    /// Rereads the same context OFD through the existing healthy context recipe.
    ///
    /// # Errors
    /// Retains original info/read/liveness or closed-source failure before return.
    pub fn observe_context_retaining_v1(&mut self, process: &PidFd, original: &mut PidFdProcOriginalsV1)
        -> Result<&[u8]>
    {
        if original.enter_once().is_err() { self.fence(); return Err(closed()); }
        original.context_result = Some((|| {
            let operation = self.begin(ObservationPhaseV1::Ready)?;
            let result = operation.observations.observe_context_inner_observed(process, Some(original));
            operation.finish(result, ObservationPhaseV1::Ready)
        })());
        original.require_context_result()?;
        Ok(&self.context.current)
    }
}

fn error<T, E: StdError + 'static>(slot: &Option<std::result::Result<T, E>>)
    -> Option<&(dyn StdError + 'static)>
{
    slot.as_ref()?.as_ref().err().map(|cause| cause as _)
}

#[cfg(test)]
mod tests {
    use std::os::fd::AsRawFd as _;

    use super::*;

    #[test]
    fn available_stat_prefix_keeps_native_capture_and_closed_source() {
        let process = PidFd::open(std::num::NonZeroU32::new(std::process::id()).unwrap()).unwrap();
        let mut source = process.prepare_proc_observations_v1();
        let mut capture = PidFdProcOriginalsV1::new();
        let identity = source.capture_stat_retaining_v1(&process, &mut capture).unwrap();
        let original_file = source.stat.file.as_ref().unwrap().as_raw_fd();
        assert_eq!(Some(identity), source.original_identity);
        assert!(capture.failure().is_none());
        assert!(matches!(capture.identity.before, Some(Ok(_))));
        assert!(matches!(capture.identity.stat.filesystem, Some(Ok(_))));

        // The same real source closes on its missing-context healthy gate.
        assert!(source.observe_identity(&process).is_err());
        assert!(matches!(source.phase, ObservationPhaseV1::Closed));
        let mut completed_only = PidFdNegativeIdentityOriginalV1::new();
        assert!(source.prepare_negative_identity_once_into(&mut completed_only).is_err());

        let mut owed = PidFdNegativeIdentityOriginalV1::new();
        source.prepare_available_negative_identity_once_into_v1(&mut owed).unwrap();
        owed.observe_once(&process).unwrap();
        assert!(matches!(source.phase, ObservationPhaseV1::Closed));
        assert_eq!(source.stat.file.as_ref().unwrap().as_raw_fd(), original_file);
        rustix::io::fcntl_getfd(source.stat.file.as_ref().unwrap()).unwrap();
        assert!(source.observe_identity(&process).is_err());
        assert!(owed.observe_once(&process).is_err());
        assert!(capture.failure().is_none());
    }

    #[test]
    fn repeated_retained_stat_closes_source_without_replacing_native_results() {
        let process = PidFd::open(std::num::NonZeroU32::new(std::process::id()).unwrap()).unwrap();
        let mut source = process.prepare_proc_observations_v1();
        let mut capture = PidFdProcOriginalsV1::new();
        let identity = source.capture_stat_retaining_v1(&process, &mut capture).unwrap();
        let file = source.stat.file.as_ref().unwrap().as_raw_fd();

        assert!(source.capture_stat_retaining_v1(&process, &mut capture).is_err());
        let first = capture.failure().unwrap() as *const dyn StdError as *const ();
        assert!(source.capture_stat_retaining_v1(&process, &mut capture).is_err());
        assert_eq!(capture.failure().unwrap() as *const dyn StdError as *const (), first);
        assert_eq!(capture.identity_result().unwrap(), identity);
        assert!(matches!(source.phase, ObservationPhaseV1::Closed));
        assert_eq!(source.stat.file.as_ref().unwrap().as_raw_fd(), file);
        rustix::io::fcntl_getfd(source.stat.file.as_ref().unwrap()).unwrap();
    }
}
