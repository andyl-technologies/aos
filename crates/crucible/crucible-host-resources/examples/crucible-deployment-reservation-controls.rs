//! Exercises genuine process-reservation ownership in dedicated Linux processes.
//!
//! `all` launches four closed control modes without lowering the launcher's
//! limits. Each mode changes only its own process limits and reports the actual
//! kernel pairs. `inherited` also launches a fresh executable to test inherited
//! ceilings; it makes no claim about retaining an owner across fork or exec.
//! These operational controls issue no Source, node, execution or Ready grant.
//!
//! ```text
//! crucible-deployment-reservation-controls all
//! crucible-deployment-reservation-controls handoff
//! crucible-deployment-reservation-controls birth-refusal
//! crucible-deployment-reservation-controls inherited
//! crucible-deployment-reservation-controls sticky-revocation
//! ```

use crucible_host_resources::{
    LinuxProcessCeilingsData, LinuxProcessLimits, LinuxProcessSupervisorError,
    OriginalDeploymentResourceReservation,
};
use rustix::process::{Resource, Rlimit, setrlimit};
use std::{error::Error, io, process::Command, sync::mpsc, thread};

type ControlResult<T = ()> = Result<T, Box<dyn Error>>;

const POLICY: LinuxProcessLimits = LinuxProcessLimits {
    cpu_seconds: 60,
    address_space_bytes: 1_073_741_824,
    descriptors: 256,
};

const INHERITED_CAP: LinuxProcessLimits = LinuxProcessLimits {
    cpu_seconds: 30,
    address_space_bytes: 536_870_912,
    descriptors: 128,
};

const MODES: [&str; 4] = ["handoff", "birth-refusal", "inherited", "sticky-revocation"];

fn require(condition: bool, message: &'static str) -> io::Result<()> {
    if condition {
        Ok(())
    } else {
        Err(io::Error::other(message))
    }
}

fn main() -> ControlResult {
    let mut arguments = std::env::args_os().skip(1);
    let mode = arguments
        .next()
        .ok_or_else(|| io::Error::other("missing mode"))?;
    require(arguments.next().is_none(), "unexpected argument")?;
    match mode.to_str() {
        Some("all") => {
            let before = LinuxProcessCeilingsData::current();
            for mode in MODES {
                run_child(mode)?;
            }
            require(
                before == LinuxProcessCeilingsData::current(),
                "launcher limits changed",
            )?;
            println!(
                "all: launcher_pid={} unchanged={before:?}",
                std::process::id()
            );
            Ok(())
        }
        Some("handoff") => handoff(),
        Some("birth-refusal") => birth_refusal(),
        Some("inherited") => inherited(),
        Some("inherited-child") => inherited_child(),
        Some("sticky-revocation") => sticky_revocation(),
        _ => Err(io::Error::other("unknown control mode").into()),
    }
}

fn run_child(mode: &str) -> ControlResult {
    let status = Command::new(std::env::current_exe()?).arg(mode).status()?;
    require(status.success(), "control child failed")?;
    Ok(())
}

fn installed_owner() -> ControlResult<OriginalDeploymentResourceReservation> {
    let before = LinuxProcessCeilingsData::current();
    let mut output = None;
    OriginalDeploymentResourceReservation::install_before_actors_into(&mut output, POLICY)?;
    let owner = output.ok_or_else(|| io::Error::other("missing completed original"))?;
    require(
        owner.failure_data().is_none(),
        "completed original has failure",
    )?;
    require(
        owner.accepted_policy_data() == POLICY,
        "accepted policy changed",
    )?;
    require(
        LinuxProcessCeilingsData::current() == target_for(before, POLICY),
        "installation differs from inherited/requested minimum",
    )?;
    check_installed(&owner)?;
    Ok(owner)
}

fn check_installed(owner: &OriginalDeploymentResourceReservation) -> ControlResult {
    let installed = owner.reserved_policy_data()?;
    let kernel = LinuxProcessCeilingsData::current();
    for (actual, value) in [
        (kernel.cpu, installed.cpu_seconds),
        (kernel.address_space, installed.address_space_bytes),
        (kernel.descriptors, installed.descriptors),
    ] {
        require(
            actual == finite(value),
            "reserved DATA differs from actual kernel pair",
        )?;
    }
    require(
        installed.cpu_seconds <= POLICY.cpu_seconds,
        "CPU policy raised",
    )?;
    require(
        installed.address_space_bytes <= POLICY.address_space_bytes,
        "AS policy raised",
    )?;
    require(
        installed.descriptors <= POLICY.descriptors,
        "NOFILE policy raised",
    )?;
    owner.authenticate_current()?;
    println!(
        "pid={} accepted={POLICY:?} reserved={installed:?} kernel={kernel:?}",
        std::process::id()
    );
    Ok(())
}

fn finite(value: u64) -> Rlimit {
    Rlimit {
        current: Some(value),
        maximum: Some(value),
    }
}

fn require_spent() -> ControlResult {
    let before = LinuxProcessCeilingsData::current();
    let mut retry = None;
    require(
        OriginalDeploymentResourceReservation::install_before_actors_into(&mut retry, POLICY)
            == Err(LinuxProcessSupervisorError::DuplicateOperation),
        "process issuance renewed",
    )?;
    require(retry.is_none(), "duplicate populated a new original")?;
    require(
        before == LinuxProcessCeilingsData::current(),
        "duplicate changed kernel limits",
    )?;
    Ok(())
}

fn handoff() -> ControlResult {
    // Installation completes before the first actor is created.
    let owner = installed_owner()?;
    let lease = owner.lease()?;
    let context = owner.read_context()?;
    lease.authenticate_in(&context)?;
    require(
        context.reserved_policy_data()? == owner.reserved_policy_data()?,
        "context changed budget",
    )?;

    let original_thread = thread::current().id();
    let transferred = lease.clone();
    let actor = thread::Builder::new()
        .name("reservation-handoff".into())
        .spawn(move || {
            let actor_thread = thread::current().id();
            transferred.authenticate_current()?;
            Ok::<_, LinuxProcessSupervisorError>((transferred, actor_thread))
        })?;
    let (returned, actor_thread) = actor
        .join()
        .map_err(|_| io::Error::other("actor panicked"))??;
    require(
        actor_thread != original_thread,
        "lease did not cross threads",
    )?;
    returned.authenticate_in(&context)?;
    lease.authenticate_current()?;
    require_spent()?;
    println!("handoff: creator={original_thread:?} actor={actor_thread:?} same_original=true");

    drop(owner);
    require(
        returned.authenticate_current() == Err(LinuxProcessSupervisorError::ForeignAuthority),
        "drop did not revoke returned lease",
    )?;
    require(
        lease.authenticate_current() == Err(LinuxProcessSupervisorError::ForeignAuthority),
        "drop did not revoke original lease",
    )?;
    require_spent()?;
    println!("handoff: owner_dropped=true leases_revoked=true process_once=true");
    Ok(())
}

fn birth_refusal() -> ControlResult {
    let before = LinuxProcessCeilingsData::current();
    let (ready_send, ready_receive) = mpsc::channel();
    let (release_send, release_receive) = mpsc::channel::<()>();
    let actor = thread::Builder::new()
        .name("preexisting-actor".into())
        .spawn(move || {
            ready_send
                .send(())
                .map_err(|_| io::Error::other("ready receiver lost"))?;
            // The sender remains owned by the caller through the installation call.
            // Disconnection releases the actor even if a later assertion refuses.
            let _ = release_receive.recv();
            Ok::<_, io::Error>(())
        })?;

    let mut output = None;
    let refusal = (|| -> ControlResult {
        ready_receive.recv()?;
        require(
            OriginalDeploymentResourceReservation::install_before_actors_into(&mut output, POLICY)
                == Err(LinuxProcessSupervisorError::ForeignAuthority),
            "installation accepted a preexisting actor",
        )?;
        let owner = output
            .as_ref()
            .ok_or_else(|| io::Error::other("failed original was lost"))?;
        require(
            owner.failure_data() == Some(LinuxProcessSupervisorError::ForeignAuthority),
            "original failure changed",
        )?;
        require(
            owner.accepted_policy_data() == POLICY,
            "failed accepted policy changed",
        )?;
        require(
            owner.reserved_policy_data()
                == Err(LinuxProcessSupervisorError::OutstandingObligations),
            "failed original invented installed DATA",
        )?;
        require(
            owner.authenticate_current() == Err(LinuxProcessSupervisorError::ForeignAuthority),
            "failed original authenticated",
        )?;
        require(owner.lease().is_err(), "failed original lent a lease")?;
        require(
            before == LinuxProcessCeilingsData::current(),
            "birth refusal changed limits",
        )?;
        require_spent()?;
        Ok(())
    })();
    drop(release_send);
    let joined = actor
        .join()
        .map_err(|_| io::Error::other("preexisting actor panicked"));
    refusal?;
    joined??;

    require_spent()?;
    drop(output);
    require_spent()?;
    require(
        before == LinuxProcessCeilingsData::current(),
        "failed/drop path changed limits",
    )?;
    println!(
        "birth-refusal: pid={} failure=ForeignAuthority output_retained=true actor_joined=true process_once=true unchanged={before:?}",
        std::process::id()
    );
    Ok(())
}

fn capped(old: Rlimit, requested: u64) -> Rlimit {
    let target = old
        .current
        .unwrap_or(requested)
        .min(old.maximum.unwrap_or(requested))
        .min(requested);
    finite(target)
}

fn target_for(
    before: LinuxProcessCeilingsData,
    policy: LinuxProcessLimits,
) -> LinuxProcessCeilingsData {
    LinuxProcessCeilingsData {
        cpu: capped(before.cpu, policy.cpu_seconds),
        address_space: capped(before.address_space, policy.address_space_bytes),
        descriptors: capped(before.descriptors, policy.descriptors),
    }
}

fn inherited() -> ControlResult {
    let before = LinuxProcessCeilingsData::current();
    let target = target_for(before, INHERITED_CAP);
    // Refuse an environment that already exceeds the proposed test envelope.
    // This DATA census creates no completed reservation or replacement owner.
    target.authenticate_existing()?;
    // This dedicated process sets the actual envelope inherited by a fresh exec.
    // It holds no reservation whose process latch could be mistaken for transfer.
    setrlimit(Resource::Cpu, target.cpu)?;
    setrlimit(Resource::As, target.address_space)?;
    setrlimit(Resource::Nofile, target.descriptors)?;
    require(
        LinuxProcessCeilingsData::current() == target,
        "inherited envelope install changed",
    )?;
    println!(
        "inherited-parent: pid={} before={before:?} target={target:?}",
        std::process::id()
    );
    run_child("inherited-child")?;
    require(
        LinuxProcessCeilingsData::current() == target,
        "child changed parent limits",
    )?;
    Ok(())
}

fn inherited_child() -> ControlResult {
    let before = LinuxProcessCeilingsData::current();
    for (actual, cap) in [
        (before.cpu, INHERITED_CAP.cpu_seconds),
        (before.address_space, INHERITED_CAP.address_space_bytes),
        (before.descriptors, INHERITED_CAP.descriptors),
    ] {
        require(
            actual.current == actual.maximum
                && actual
                    .current
                    .is_some_and(|value| value > 0 && value <= cap),
            "missing stricter inherited finite pair",
        )?;
    }
    let owner = installed_owner()?;
    let installed = owner.reserved_policy_data()?;
    require(
        before == LinuxProcessCeilingsData::current(),
        "reservation raised inherited pair",
    )?;
    require(
        installed.cpu_seconds < POLICY.cpu_seconds
            && installed.address_space_bytes < POLICY.address_space_bytes
            && installed.descriptors < POLICY.descriptors,
        "accepted policy was substituted for inherited reservation",
    )?;
    let lease = owner.lease()?;
    lease.authenticate_in(&owner.read_context()?)?;
    println!(
        "inherited-child: pid={} inherited_preserved=true accepted_strictly_larger=true",
        std::process::id()
    );
    Ok(())
}

fn sticky_revocation() -> ControlResult {
    let owner = installed_owner()?;
    let lease = owner.lease()?;
    let before = LinuxProcessCeilingsData::current();
    let old_soft = before
        .descriptors
        .current
        .ok_or_else(|| io::Error::other("missing installed soft limit"))?;
    let hard = before
        .descriptors
        .maximum
        .ok_or_else(|| io::Error::other("missing installed hard limit"))?;
    require(
        old_soft > 1 && old_soft <= hard,
        "cannot safely perturb descriptor limit",
    )?;
    let changed = Rlimit {
        current: Some(old_soft - 1),
        maximum: Some(hard),
    };
    setrlimit(Resource::Nofile, changed)?;
    let observed = LinuxProcessCeilingsData::current();
    let first_refusal = lease.authenticate_current();
    // Restore only this child's soft limit, never raise the original hard limit.
    // Capture the refusal before restoring, and defer assertions until afterward.
    setrlimit(Resource::Nofile, before.descriptors)?;
    require(
        observed.descriptors == changed
            && observed.cpu == before.cpu
            && observed.address_space == before.address_space,
        "wrong kernel perturbation",
    )?;
    require(
        first_refusal == Err(LinuxProcessSupervisorError::ForeignAuthority),
        "changed enforcement authenticated",
    )?;
    require(
        LinuxProcessCeilingsData::current() == before,
        "soft limit restoration failed",
    )?;
    require(
        lease.authenticate_current() == Err(LinuxProcessSupervisorError::ForeignAuthority),
        "restoration renewed revoked lease",
    )?;
    require(
        owner.authenticate_current() == Err(LinuxProcessSupervisorError::ForeignAuthority),
        "restoration renewed revoked owner",
    )?;
    require(
        owner.lease().is_err() && owner.read_context().is_err(),
        "revoked owner issued acceptance",
    )?;
    require_spent()?;
    println!(
        "sticky-revocation: pid={} observed={observed:?} restored={before:?} first={first_refusal:?} still_revoked=true",
        std::process::id()
    );
    Ok(())
}
