//! Private process-group containment and authentic complete reclamation receipts.
//!
//! The launcher creates a fresh process group before native code executes. The
//! installed DMTCP coordinator keeps that group (its daemon path does not call
//! setsid). Termination never settles original modeled output: all immutable
//! prefixes, native buffers, uncertainty records and source images remain held.

use std::os::unix::process::ExitStatusExt;

use super::*;
use crucible_node_contract::canonical;
use rustix::process::{Pid, Signal, getpgid, kill_process_group};

/// Retains original containment scope when custody moves to supervision.
#[derive(Debug)]
pub struct Gem5QuarantineCustody {
    pid: u32,
    start_ticks: String,
    deadline: Instant,
    reaped: Option<std::process::ExitStatus>,
    proof: Option<Gem5ReclamationProof>,
}

impl Gem5QuarantineCustody {
    /// Returns the original private process group that received termination.
    pub fn process_group(&self) -> u32 {
        self.pid
    }
}

/// Proves actual child reaping and disappearance of every private group member.
///
/// This receipt proves operational reclamation only. It conveys no permission
/// to discard original modeled output, publish an uncertain outcome, or reuse
/// the original incarnation. Its constructor remains inside native supervision.
#[derive(Debug)]
pub struct Gem5ReclamationProof {
    owner: Id,
    incarnation: Id,
    generation: U64,
    evidence: ContentRef,
    bytes: Vec<u8>,
}

impl Gem5ReclamationProof {
    /// Returns the original owner whose native resources have been reclaimed.
    pub fn owner(&self) -> &Id {
        &self.owner
    }

    /// Returns the original reclaimed native incarnation.
    pub fn incarnation(&self) -> &Id {
        &self.incarnation
    }

    /// Returns the original fencing generation without rebasing old authority.
    pub fn generation(&self) -> U64 {
        self.generation
    }

    /// Returns immutable original kernel-reclamation evidence.
    pub fn evidence(&self) -> (&ContentRef, &[u8]) {
        (&self.evidence, &self.bytes)
    }
}

impl Gem5NativeProcess {
    /// Terminates the actual private native group while retaining original custody.
    ///
    /// A kill request is not a reclamation receipt. Repeated calls retain the
    /// same original quarantine and never signal a replacement process group.
    ///
    /// # Errors
    /// Refuses missing actual child custody, a changed kernel identity, a group
    /// outside the launch scope, or failure to signal the original private group.
    pub fn begin_quarantine(&mut self) -> Result<(), ProviderError> {
        let child = self.child.as_mut().ok_or(ProviderError::Correlation(
            "gem5 quarantine omits original child",
        ))?;
        begin_quarantine(child, &self.launch, &mut self.stream, &mut self.quarantine)
    }

    /// Polls actual child and auxiliary-group reclamation without servicing events.
    ///
    /// Returns no receipt while any private-group PID remains. Original modeled
    /// custody is retained even after the kernel has reclaimed every process.
    ///
    /// # Errors
    /// Refuses polling before quarantine, changed native identity, kernel census
    /// failure, exhausted finite census credit, or an expired operational budget.
    pub fn poll_reclamation(&mut self) -> Result<Option<&Gem5ReclamationProof>, ProviderError> {
        let child = self.child.as_mut().ok_or(ProviderError::Correlation(
            "gem5 reclamation omits original child",
        ))?;
        poll_reclamation(child, &self.launch, &mut self.quarantine)
    }
}

impl Gem5NativeCustody {
    /// Terminates its original private group while retaining all native obligations.
    ///
    /// This supports fallback supervision after failed readiness or driver Drop.
    /// No event is serviced and no modeled output is discharged.
    ///
    /// # Errors
    /// Refuses changed kernel identity, an escaped group, or signal failure.
    pub fn begin_quarantine(&mut self) -> Result<(), ProviderError> {
        begin_quarantine(
            &mut self.child,
            &self.launch,
            &mut self.stream,
            &mut self.quarantine,
        )
    }

    /// Polls genuine child and complete auxiliary-group reaping in supervision.
    ///
    /// The receipt preserves original scope. All saved outcomes, images and
    /// publication obligations remain in the capsule after native reclamation.
    ///
    /// # Errors
    /// Refuses missing quarantine, changed child identity, census failures,
    /// exhausted finite census credit, or an expired operational budget.
    pub fn poll_reclamation(&mut self) -> Result<Option<&Gem5ReclamationProof>, ProviderError> {
        poll_reclamation(&mut self.child, &self.launch, &mut self.quarantine)
    }
}

fn begin_quarantine(
    child: &mut Child,
    launch: &Gem5Launch,
    stream: &mut Option<UnixStream>,
    quarantine: &mut Option<Gem5QuarantineCustody>,
) -> Result<(), ProviderError> {
    if quarantine.is_some() {
        return Ok(());
    }
    let pid = child.id();
    let start_ticks = closure::kernel_start_ticks(pid)?;
    let native_pid = Pid::from_raw(
        i32::try_from(pid)
            .map_err(|_| ProviderError::Correlation("gem5 kernel pid exceeds native range"))?,
    )
    .ok_or(ProviderError::Correlation(
        "gem5 kernel pid is unrepresentable",
    ))?;
    if getpgid(Some(native_pid)).map_err(std::io::Error::from)? != native_pid {
        return Err(ProviderError::Correlation(
            "gem5 native process escaped its private launch group",
        ));
    }
    *quarantine = Some(Gem5QuarantineCustody {
        pid,
        start_ticks,
        deadline: super::deadline(launch.timeout)?,
        reaped: None,
        proof: None,
    });
    // Before actual reaping the child/group identity cannot be recycled.
    kill_process_group(native_pid, Signal::KILL).map_err(std::io::Error::from)?;
    if let Some(stream) = stream.take() {
        stream.shutdown(std::net::Shutdown::Both)?;
    }
    Ok(())
}

fn poll_reclamation<'a>(
    child: &mut Child,
    launch: &Gem5Launch,
    quarantine: &'a mut Option<Gem5QuarantineCustody>,
) -> Result<Option<&'a Gem5ReclamationProof>, ProviderError> {
    let state = quarantine.as_mut().ok_or(ProviderError::Conflict(
        "gem5 reclamation precedes quarantine",
    ))?;
    if state.proof.is_none() {
        if state.reaped.is_none() {
            if child.id() != state.pid {
                return Err(ProviderError::Correlation(
                    "gem5 reclamation child identity changed",
                ));
            }
            state.reaped = child.try_wait()?;
        }
        let members = group_members(state.pid)?;
        if let Some(status) = state.reaped.filter(|_| members.is_empty()) {
            let bytes = canonical::canonical_json(&json!({
                "schema":"crucible.gem5.native-reclamation.v1",
                "owner":launch.owner,"incarnation":launch.incarnation,
                "generation":launch.generation,"pid":state.pid.to_string(),
                "start_ticks":state.start_ticks,"source_scope":closure::source_scope(launch)?,
                "exit_code":status.code(),"exit_signal":status.signal(),
                "remaining_group_members":[],
            }))?;
            state.proof = Some(Gem5ReclamationProof {
                owner: launch.owner.clone(),
                incarnation: launch.incarnation.clone(),
                generation: launch.generation,
                evidence: canonical::content_ref(&bytes, "application/json")?,
                bytes,
            });
        } else if operational_now() >= state.deadline {
            return Err(ProviderError::Conflict(
                "gem5 private group reclamation deadline expired",
            ));
        }
    }
    Ok(state.proof.as_ref())
}

fn group_members(group: u32) -> Result<Vec<u32>, ProviderError> {
    let mut members = Vec::new();
    let mut entries = 0usize;
    for entry in fs::read_dir("/proc")? {
        entries += 1;
        if entries > 100_000 {
            return Err(ProviderError::ResourceExhausted(
                "gem5 kernel process census",
            ));
        }
        let entry = entry?;
        let Some(pid) = entry
            .file_name()
            .to_str()
            .and_then(|name| name.parse::<u32>().ok())
        else {
            continue;
        };
        let path = entry.path().join("stat");
        let mut bytes = Vec::new();
        let file = match File::open(path) {
            Ok(file) => file,
            Err(error) if error.kind() == std::io::ErrorKind::NotFound => continue,
            Err(error) => return Err(error.into()),
        };
        file.take(65537).read_to_end(&mut bytes)?;
        let text = std::str::from_utf8(&bytes)
            .map_err(|_| ProviderError::Frame("gem5 kernel process stat encoding"))?;
        let close = text
            .rfind(')')
            .ok_or(ProviderError::Frame("gem5 kernel process stat shape"))?;
        if bytes.len() > 65536 {
            return Err(ProviderError::ResourceExhausted("gem5 kernel process stat"));
        }
        let pgrp = text[close + 1..]
            .split_ascii_whitespace()
            .nth(2)
            .ok_or(ProviderError::Frame("gem5 kernel process group omitted"))?
            .parse::<u32>()
            .map_err(|_| ProviderError::Frame("gem5 kernel process group invalid"))?;
        if pgrp == group {
            if members.len() >= 4096 {
                return Err(ProviderError::ResourceExhausted(
                    "gem5 private auxiliary process roster",
                ));
            }
            members.push(pid);
        }
    }
    members.sort_unstable();
    Ok(members)
}
