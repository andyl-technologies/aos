//! Fixed image-owned worker entry for the Mount-owned session role.
//!
//! Startup owns exactly five inherited roles. It admits actual execution and
//! labelled kernel objects before emitting a preparation-only HELLO. It never
//! reads FUSE requests, exposes metadata, accepts a backing FD or acknowledges
//! readiness before a separately genuine held Root/Mount read-grant dispatch.

use std::process::ExitCode;

use aos_filesystem_fuse::worker_session::{
    WORKER_PREPARATION_PLAN_BYTES_V1, WorkerPreparationPlanV1,
};
use aos_sandbox_linux::boot::KernelBootId;
use aos_sandbox_linux::fuse_worker_startup::FixedFuseWorkerStartupV1;
use aos_sandbox_linux::immutable_file::SealedMemfdMapping;
use aos_sandbox_linux::seqpacket::bounded::boottime;

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
    let (plan, session) = startup.into_plan_and_session();
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
            session.send_preparation_record(&original.hello()?)?;
            // Positive metadata/backing dispatch requires the actual joined
            // Root/Mount consumer producer. Do not convert this HELLO or plan
            // into a read grant or silently invoke the dormant FUSE runner.
            session.wait_for_owner_cancellation()?;
            Ok(())
        },
    )??;
    Ok(())
}
