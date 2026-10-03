//! Serves nonauthorizing state on the one originally accepted normal stream.
//!
//! The bootstrap was consumed as inert discrimination DATA. Strict subject
//! reporting begins before HELLO; SELECT and terminal/trailing bytes are all
//! independently checked. The existing Policy writer remains held through ACK.

use std::os::fd::OwnedFd;

use aos_sandbox_core::{ProjectId, SandboxId};

use super::super::PolicyCompilerStateReadbackOwnerV1;
use super::ConsumerReadFlightErrorV1 as Error;
use super::transport::{Deadline, Flight};
use super::wire::{Correlation, Phase, STATE_PREFIX_BYTES, maximum_state_bytes, take};
use crate::normal_root::{OriginalControllerPolicyPeerV1, ProductionNormalRootStartupV1};

// Field drop order shuts down the original endpoint before releasing Policy.
// This is PRE-ROOT ownership only, not a future positive ambiguity container.
struct StateFlight {
    flight: Flight,
    #[cfg(test)]
    _before_policy_drop: Option<tests::DropProbe>,
    policy: PolicyCompilerStateReadbackOwnerV1,
}

/// Serves PRE-ROOT Policy metadata without acquiring Root read authority.
///
/// The daemon moves its accepted stream once after exact bootstrap selection.
/// This requires genuine normal startup, never a legacy/recovery fallback.
/// CONTINUE always returns DENIED before any Root writer/gate/signing action.
///
/// # Errors
///
/// Rejects changed original startup/Controller peer, deadline, frames/subjects,
/// missing or unsafe existing Policy state, unavailable target or trailing data.
pub fn serve_consumer_read_policy_state_v1(
    original: OwnedFd,
    startup: &ProductionNormalRootStartupV1,
    bootstrap: [u8; 32],
) -> Result<(), Error> {
    let correlation = Correlation::from_bootstrap(&bootstrap)?;
    let deadline = Deadline::capture(correlation.deadline)?;
    startup.recheck()?;
    deadline.require_current()?;
    let mut flight = Flight::adopt(original, correlation, deadline)?;
    let peer: OriginalControllerPolicyPeerV1<'_> =
        startup.observe_controller_policy_peer(flight.stream())?;
    deadline.require_current()?;
    let mut check =
        |stream: &_, chunk: Option<&aos_sandbox_linux::unix_stream::UnixStreamSubjectChunk>| {
            match chunk {
                Some(chunk) => peer.require_chunk(stream, chunk)?,
                None => peer.recheck_stream(stream)?,
            }
            Ok(())
        };
    flight.send_header(Phase::Hello, 16, &mut check)?;
    flight.write(&deadline.boot(), &mut check)?;

    // Existing-only and opened once. No alternate Root journal is involved.
    let policy = PolicyCompilerStateReadbackOwnerV1::open_existing_fixed_protected()?;
    let mut state_flight = StateFlight {
        flight,
        #[cfg(test)]
        _before_policy_drop: None,
        policy,
    };
    let StateFlight { flight, policy, .. } = &mut state_flight;
    deadline.require_current()?;
    let (phase, length) = flight.header(&mut check)?;
    if phase != Phase::Select {
        return Err(Error::Protocol);
    }
    let selector = flight.read_exact(length, &mut check)?;
    let project = ProjectId::from_bytes(take(&selector, 0)?);
    let sandbox = SandboxId::from_bytes(take(&selector, 16)?);
    if project.as_bytes() == &[0; 16] || sandbox.as_bytes() == &[0; 16] {
        return Err(Error::Protocol);
    }

    // The callback returns unit. Its local transport diagnostics cannot carry
    // a caller-supplied owning Prepared/Pending outcome behind postflight.
    let mut diagnostic = Ok(());
    policy.with_current_policy_claim(project, sandbox, |claim| {
        diagnostic = (|| -> Result<(), Error> {
            let mut held_check = |stream: &_,
                                  chunk: Option<
                &aos_sandbox_linux::unix_stream::UnixStreamSubjectChunk,
            >| {
                check(stream, chunk)?;
                claim.recheck()?;
                Ok(())
            };
            flight.checked(&mut held_check, None)?;
            let candidate = claim.candidate_bytes();
            let length = STATE_PREFIX_BYTES
                .checked_add(candidate.len())
                .ok_or(Error::Protocol)?;
            if length > maximum_state_bytes()? {
                return Err(Error::Protocol);
            }
            let (current, envelope) = claim.envelopes();
            let (_, generation) = claim.candidate();
            let mut prefix = [0; STATE_PREFIX_BYTES];
            prefix[..32].copy_from_slice(current.as_bytes());
            prefix[32..64].copy_from_slice(envelope.as_bytes());
            prefix[64..72].copy_from_slice(&generation.to_be_bytes());
            prefix[72..].copy_from_slice(
                &u32::try_from(candidate.len())
                    .map_err(|_| Error::Protocol)?
                    .to_be_bytes(),
            );
            flight.send_header(Phase::State, length, &mut held_check)?;
            flight.write(&prefix, &mut held_check)?;
            flight.write(candidate, &mut held_check)?;
            let (terminal, length) = flight.header(&mut held_check)?;
            let reply = terminal_reply(terminal, length)?;
            // EOF is part of this exact terminal command. Any trailing byte is
            // subject-checked and rejected before acknowledgement.
            flight.require_eof(&mut held_check)?;
            flight.send_header(reply, 0, &mut held_check)?;
            flight.finish_sending()?;
            flight.checked(&mut held_check, None)
        })();
    })?;
    diagnostic?;
    deadline.require_current()
}

fn terminal_reply(phase: Phase, length: usize) -> Result<Phase, Error> {
    match (phase, length) {
        (Phase::Abort, 0) => Ok(Phase::Aborted),
        // Deliberately contains no Root hold gate, journal, signer or issuer.
        (Phase::Continue, 0) => Ok(Phase::Denied),
        _ => Err(Error::Protocol),
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::io::Read as _;
    use std::os::unix::fs::{MetadataExt as _, PermissionsExt as _};
    use std::os::unix::net::UnixStream;

    // Test-only observation runs between the actual endpoint and Policy field
    // destructors. It supplies no role, startup, request or read authority.
    pub(super) struct DropProbe {
        peer: UnixStream,
        root: std::path::PathBuf,
        uid: u32,
    }

    impl Drop for DropProbe {
        fn drop(&mut self) {
            let mut byte = [0];
            assert_eq!(self.peer.read(&mut byte).unwrap(), 0);
            assert!(
                crate::Journal::open_existing_protected_at_uid(
                    &self.root,
                    super::super::super::protected_owner::POLICY_STATE_JOURNAL,
                    super::super::super::protected_owner::policy_state_journal_limits(),
                    self.uid
                )
                .is_err()
            );
        }
    }

    #[test]
    fn original_endpoint_closes_before_actual_policy_writer_is_released() {
        let root = tempfile::tempdir().unwrap();
        std::fs::set_permissions(root.path(), std::fs::Permissions::from_mode(0o700)).unwrap();
        let policy = crate::policy_compiler::resolved_policy::tests::open(root.path());
        let uid = std::fs::metadata(root.path()).unwrap().uid();
        let now = rustix::time::clock_gettime(rustix::time::ClockId::Boottime);
        let cutoff = now.tv_sec as u64 * 1_000_000_000 + now.tv_nsec as u64 + 2_000_000_000;
        let deadline = Deadline::capture(cutoff).unwrap();
        let (original, peer) = UnixStream::pair().unwrap();
        peer.set_read_timeout(Some(std::time::Duration::from_secs(1)))
            .unwrap();
        let flight = Flight::adopt(
            original.into(),
            Correlation {
                nonce: [1; 16],
                deadline: cutoff,
            },
            deadline,
        )
        .unwrap();
        drop(StateFlight {
            flight,
            _before_policy_drop: Some(DropProbe {
                peer,
                root: root.path().to_owned(),
                uid,
            }),
            policy,
        });
        assert!(
            crate::Journal::open_existing_protected_at_uid(
                root.path(),
                super::super::super::protected_owner::POLICY_STATE_JOURNAL,
                super::super::super::protected_owner::policy_state_journal_limits(),
                uid
            )
            .is_ok()
        );
    }

    #[test]
    fn only_abort_acknowledges_and_continue_is_always_denied() {
        assert_eq!(terminal_reply(Phase::Abort, 0).unwrap(), Phase::Aborted);
        assert_eq!(terminal_reply(Phase::Continue, 0).unwrap(), Phase::Denied);
        for phase in [
            Phase::Hello,
            Phase::Select,
            Phase::State,
            Phase::Aborted,
            Phase::Denied,
        ] {
            assert!(terminal_reply(phase, 0).is_err());
        }
        assert!(terminal_reply(Phase::Continue, 1).is_err());
    }
}
