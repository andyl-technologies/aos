//! Fixed image-owned worker entry for the Mount-owned session role.
//!
//! Startup owns exactly five inherited roles. It admits actual execution and
//! labelled kernel objects before receiving a fresh preparation challenge.
//! It consumes only kernel INIT in the original held preparation flight. It
//! never dispatches metadata, accepts a backing FD or acknowledges readiness
//! before a separately genuine held Root/Mount read-grant dispatch.

use std::process::ExitCode;

use aos_filesystem_fuse::worker_kernel_init::PreparedFixedWorkerKernelSessionV1;

use aos_filesystem_fuse::worker_session::{
    WORKER_PREPARATION_PLAN_BYTES_V1, WorkerPreparationPlanV1,
};
use aos_sandbox_linux::boot::KernelBootId;
use aos_sandbox_linux::fuse_worker_startup::FixedFuseWorkerStartupV1;
use aos_sandbox_linux::immutable_file::SealedMemfdMapping;
use aos_sandbox_linux::seqpacket::SeqpacketError;
use aos_sandbox_linux::seqpacket::bounded::boottime;
use aos_sandbox_protocol::fuse_worker_preparation::{
    WORKER_RENDEZVOUS_BYTES_V2, WorkerRendezvousChallengeV2,
};

fn main() -> ExitCode {
    match run() {
        Ok(()) => ExitCode::SUCCESS,
        Err(error) => {
            eprintln!("fixed FUSE worker failed: {error}");
            ExitCode::FAILURE
        }
    }
}

fn run() -> Result<(), Box<dyn std::error::Error>> {
    let mut arguments = std::env::args_os();
    let _executable = arguments.next();
    if arguments.next().as_deref() != Some(std::ffi::OsStr::new("--mount-owned-session-v1"))
        || arguments.next().is_some()
    {
        return Err("fixed worker accepts only --mount-owned-session-v1".into());
    }
    // SAFETY: this fixed entry is single-threaded, has installed no signal
    // handlers and has constructed no owners for the inherited role table.
    let startup = unsafe { FixedFuseWorkerStartupV1::capture() }?;
    let (plan, mut session) = startup.into_plan_and_session();
    SealedMemfdMapping::run(
        plan,
        WORKER_PREPARATION_PLAN_BYTES_V1 as u64,
        WORKER_PREPARATION_PLAN_BYTES_V1 as u64,
        |bytes, _| -> Result<(), Box<dyn std::error::Error>> {
            let original = WorkerPreparationPlanV1::decode(bytes)?;
            if original.kernel_boot != KernelBootId::current()?.into_bytes()
                || boottime()? >= original.preparation_deadline_boottime_ns
                || boottime()? >= original.ownership_lease_expires_boottime_ns
            {
                return Err("original worker preparation scope is stale".into());
            }
            session.recheck()?;
            // Never prequeue AOSFWH01 or use the sealed plan's prelaunch
            // challenge as freshness. Only the post-barrier profile gets a
            // reply on this same original endpoint and executing subject.
            let (challenge, subject) = loop {
                if boottime()? >= original.preparation_deadline_boottime_ns {
                    return Err("original worker rendezvous deadline elapsed".into());
                }
                match session.receive_preparation_record(WORKER_RENDEZVOUS_BYTES_V2) {
                    Ok((bytes, subject)) => {
                        let challenge =
                            WorkerRendezvousChallengeV2::decode(&bytes, &original, boottime()?)?;
                        if !subject.is_alive()? {
                            return Err("original Mount exited during challenge".into());
                        }
                        break (challenge, subject);
                    }
                    Err(SeqpacketError::WouldBlock | SeqpacketError::Interrupted) => {
                        session.wait_preparation_readiness(
                            original.preparation_deadline_boottime_ns,
                        )?;
                    }
                    Err(error) => return Err(error.into()),
                }
            };
            session.recheck()?;
            challenge.check_deadline(boottime()?)?;
            session.send_preparation_record(&challenge.reply(), &subject)?;
            let prepared = PreparedFixedWorkerKernelSessionV1::prepare_original_flight(
                session, original, &challenge, &subject,
            )?;
            // The same C session is idle after actual INIT and original Mount
            // idmap. No runner restart or metadata/backing callback is installed.
            prepared.wait_for_owner_cancellation()?;
            Ok(())
        },
    )??;
    Ok(())
}
