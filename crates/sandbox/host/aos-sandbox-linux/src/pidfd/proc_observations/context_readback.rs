//! Retains one task-context acquisition through the shared procfs reader.
//!
//! The original pidfd chooses the task. This owner retains its exact context
//! descriptor, partial bytes, path and native Results, including independently
//! owed final GET_INFO and liveness after any earlier acquisition failure.
//! Matching a context to an application role remains the caller's obligation.

use std::error::Error as StdError;

use super::identity_readback::StatCaptureOriginalsV1;
use super::*;

/// Keeps the original bounded task-context descriptor and native observations.
///
/// This DATA capture takes no pathname, PID, caller maximum or role policy.
/// Its genuine purpose owner prepays the actual dimensions, retains the same
/// supplied pidfd, and compares returned bytes to its compiled task contract.
#[must_use = "keep context acquisition originals through every owed native post"]
pub struct PidFdContextReadbackV1 {
    before: Option<Result<PidFdInfo>>,
    descriptor: ProcDescriptorV1,
    originals: StatCaptureOriginalsV1,
    read: Option<Result<()>>,
    after: Option<Result<PidFdInfo>>,
    alive: Option<Result<bool>>,
    binding: Option<Result<()>>,
    completion: Option<Result<()>>,
    entered: bool,
    closed: Option<Error>,
}

impl PidFdContextReadbackV1 {
    /// Creates inert descriptor and Result destinations without native IO.
    #[must_use]
    pub fn new() -> Self {
        Self {
            before: None,
            descriptor: ProcDescriptorV1::empty(),
            originals: StatCaptureOriginalsV1::new(),
            read: None,
            after: None,
            alive: None,
            binding: None,
            completion: None,
            entered: false,
            closed: None,
        }
    }

    /// Captures the original task context and runs independent final posts.
    ///
    /// # Errors
    /// Retains unavailable GET_INFO, proc open/metadata/read/allocation errors,
    /// excess bytes, changed task information and process exit. Reentry sticks
    /// closed and cannot overwrite an earlier cause or reopen the reservoir.
    pub fn capture_once(&mut self, original: &PidFd) -> Result<()> {
        if self.entered {
            self.closed.get_or_insert_with(closed);
            return Err(closed());
        }
        self.entered = true;
        self.before = Some(original.info());
        if let Some(Ok(before)) = self.before.as_ref() {
            self.read = Some(self.descriptor.capture_observed(
                before.pid(),
                ProcFileV1::Context,
                Some(&mut self.originals),
            ));
        }

        // These posts are independent of the entered native prefix. Neither
        // a failed GET_INFO nor a failed proc read suppresses them.
        self.after = Some(original.info());
        self.alive = Some(original.is_alive());
        self.binding = Some(match (&self.before, &self.after, &self.alive) {
            (Some(Ok(before)), Some(Ok(after)), Some(Ok(true))) if before == after => Ok(()),
            _ => Err(Error::invalid("proc context observation", "original task changed or exited")),
        });
        self.completion = Some(if matches!(self.read, Some(Ok(())))
            && matches!(self.binding, Some(Ok(())))
            && self.failure().is_none()
        {
            Ok(())
        } else {
            Err(closed())
        });
        if self.bytes().is_some() {
            Ok(())
        } else {
            Err(closed())
        }
    }

    /// Borrows completed context bytes without authenticating their role.
    #[must_use]
    pub fn bytes(&self) -> Option<&[u8]> {
        if self.failure().is_none() && matches!(self.completion, Some(Ok(()))) {
            Some(&self.descriptor.current)
        } else {
            None
        }
    }

    /// Borrows the first actual cause in the native acquisition/post order.
    #[must_use]
    pub fn failure(&self) -> Option<&(dyn StdError + 'static)> {
        failure(&self.before)
            .or_else(|| self.originals.failure())
            .or_else(|| failure(&self.read))
            .or_else(|| failure(&self.after))
            .or_else(|| failure(&self.alive))
            .or_else(|| failure(&self.binding))
            .or_else(|| failure(&self.completion))
            .or_else(|| self.closed.as_ref().map(|error| error as _))
    }

    /// Reports additional fixed construction/heap bytes, one FD and cells.
    ///
    /// The outer purpose pays the actual embedded owner separately. Requested
    /// buffers use the existing fixed context256 bound, not a caller maximum.
    #[must_use]
    pub fn receiving_demand_v1() -> Option<(usize, usize, usize)> {
        let bound = CONTEXT_BYTES.checked_add(1)?;
        let bytes = std::mem::size_of::<Self>()
            .checked_add(4usize.checked_mul(bound)?)?
            .checked_add(256)? // The shared reader's actual native scratch.
            .checked_add(64)? // /proc/ + bounded decimal u32 + /attr/current.
            .checked_add(6 * 256)?; // Native decoder, comparison and coarse Error Strings.
        // Ten parent destinations, three descriptor controls, eight capture
        // controls (including read owner), four raw-read fields, and eight
        // reached native/result/path/construction cells.
        Some((bytes, 1, 33))
    }
}

impl Default for PidFdContextReadbackV1 {
    fn default() -> Self {
        Self::new()
    }
}

fn failure<T, E: StdError + 'static>(
    value: &Option<std::result::Result<T, E>>,
) -> Option<&(dyn StdError + 'static)> {
    value.as_ref().and_then(|result| result.as_ref().err()).map(|error| error as _)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn actual_self_context_matches_the_shared_original_recipe() {
        let process = PidFd::open(std::num::NonZeroU32::new(std::process::id()).unwrap()).unwrap();
        let mut originals = PidFdContextReadbackV1::new();
        let result = originals.capture_once(&process);

        // Procfs may provide no active LSM context on the test host. Both
        // dispositions still retain the actual returned native prefix/posts.
        assert!(originals.after.is_some());
        assert!(originals.alive.is_some());
        assert!(originals.originals.path.as_deref().unwrap().ends_with("/attr/current"));
        if result.is_ok() {
            let mut ordinary = crate::pidfd::prepare_proc_observations_v1(&process);
            ordinary.capture_stat(&process).unwrap();
            assert_eq!(originals.bytes().unwrap(), ordinary.capture_context(&process).unwrap());
            assert!(originals.descriptor.file.is_some());
        } else {
            assert!(originals.failure().is_some());
            assert!(originals.bytes().is_none());
        }
    }

    #[test]
    fn real_exited_task_keeps_first_error_and_independent_posts_on_reentry() {
        use std::io::Write as _;

        let mut child = std::process::Command::new("/proc/self/exe")
            .args(["--exact", "pidfd::proc_observations::context_readback::tests::exited_task_fixture"])
            .env("AOS_CONTEXT_EXIT_FIXTURE_V1", "1")
            .stdin(std::process::Stdio::piped())
            .stdout(std::process::Stdio::null())
            .spawn()
            .unwrap();
        let process = PidFd::open(std::num::NonZeroU32::new(child.id()).unwrap()).unwrap();
        let mut release = child.stdin.take().unwrap();
        release.write_all(&[1]).unwrap();
        drop(release);
        assert!(child.wait().unwrap().success());
        let mut originals = PidFdContextReadbackV1::new();
        assert!(originals.capture_once(&process).is_err());
        let first = originals.failure().unwrap() as *const dyn StdError;
        assert!(originals.after.is_some());
        assert!(originals.alive.is_some());
        assert!(originals.capture_once(&process).is_err());
        assert!(std::ptr::addr_eq(first, originals.failure().unwrap() as *const dyn StdError));
        assert!(originals.bytes().is_none());
    }

    #[test]
    fn exited_task_fixture() {
        use std::io::Read as _;

        if std::env::var_os("AOS_CONTEXT_EXIT_FIXTURE_V1").as_deref()
            != Some(std::ffi::OsStr::new("1"))
        {
            return;
        }
        let mut release = [0];
        std::io::stdin().read_exact(&mut release).unwrap();
        assert_eq!(release, [1]);
    }

}
