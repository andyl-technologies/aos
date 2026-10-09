//! Private process-group containment and authentic complete reclamation receipts.
//!
//! The launcher creates a fresh process group before native code executes. The
//! installed DMTCP coordinator keeps that group (its daemon path does not call
//! setsid). Termination never settles original modeled output: all immutable
//! prefixes, native buffers, uncertainty records and source images remain held.

use std::os::unix::process::ExitStatusExt;

use super::*;
use crucible_node_contract::canonical;
use rustix::process::{
    Pid, Signal, WaitId, WaitIdOptions, WaitIdStatus, getpgid, kill_process_group, waitid,
};

// A retained Child alone identifies its PID, but /proc identity disappears
// after waiting. Preserve the private group anchor before any wait can reap it.
#[derive(Debug)]
pub(super) struct KernelIdentity {
    pid: u32,
    start_ticks: String,
}

pub(super) fn capture_identity(child: &Child) -> Result<KernelIdentity, ProviderError> {
    let pid = child.id();
    let identity = KernelIdentity {
        pid,
        start_ticks: closure::kernel_start_ticks(pid)?,
    };
    let native_pid = kernel_pid(pid)?;
    if getpgid(Some(native_pid)).map_err(std::io::Error::from)? != native_pid {
        return Err(ProviderError::Correlation(
            "gem5 child lacks its original private launch group",
        ));
    }
    Ok(identity)
}

fn kernel_pid(pid: u32) -> Result<Pid, ProviderError> {
    Pid::from_raw(
        i32::try_from(pid)
            .map_err(|_| ProviderError::Correlation("gem5 kernel pid exceeds native range"))?,
    )
    .ok_or(ProviderError::Correlation(
        "gem5 kernel pid is unrepresentable",
    ))
}

pub(super) fn observe_exit(child: &Child) -> Result<Option<WaitIdStatus>, ProviderError> {
    waitid(
        WaitId::Pid(kernel_pid(child.id())?),
        WaitIdOptions::EXITED | WaitIdOptions::NOHANG | WaitIdOptions::NOWAIT,
    )
    .map_err(std::io::Error::from)
    .map_err(ProviderError::from)
}

/// Retains original containment scope when custody moves to supervision.
#[derive(Debug)]
pub struct Gem5QuarantineCustody {
    pid: u32,
    start_ticks: String,
    deadline: OperationalDeadline,
    reaped: Option<std::process::ExitStatus>,
    proof: Option<Gem5ReclamationProof>,
    census_diagnostic: Option<Gem5CensusDiagnostic>,
}

impl Gem5QuarantineCustody {
    /// Returns the original private process group that received termination.
    pub fn process_group(&self) -> u32 {
        self.pid
    }

    /// Returns the first bounded kernel-census refusal retained by this custody.
    ///
    /// The diagnostic contains no process name or full stat row. It proves no
    /// reclamation and cannot change the original error or signaling policy.
    pub fn census_diagnostic(&self) -> Option<&Gem5CensusDiagnostic> {
        self.census_diagnostic.as_ref()
    }
}

/// Retains bounded original census geometry without disclosing process names.
///
/// One record belongs to the original quarantine custody. The token stores at
/// most 32 printable ASCII bytes, replacing all other bytes with `?`; its full
/// original length remains separate. A malformed row still refuses the census.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Gem5CensusDiagnostic {
    pid: u32,
    refusal_site: &'static str,
    token: [u8; 32],
    stored_token_length: usize,
    original_token_length: usize,
    field_count: Option<usize>,
}

impl Gem5CensusDiagnostic {
    /// Returns the PID named by the original census entry.
    pub fn pid(&self) -> u32 {
        self.pid
    }

    /// Returns the exact stat-field refusal site, never a native capability.
    pub fn refusal_site(&self) -> &'static str {
        self.refusal_site
    }

    /// Returns the finite sanitized original pgrp token prefix.
    pub fn pgrp_token(&self) -> &[u8] {
        &self.token[..self.stored_token_length]
    }

    /// Returns the original pgrp token length before sanitization or truncation.
    pub fn original_token_length(&self) -> usize {
        self.original_token_length
    }

    /// Returns the number of fields after the command delimiter, when observable.
    pub fn field_count(&self) -> Option<usize> {
        self.field_count
    }

    fn retain_first(
        target: &mut Option<Self>,
        pid: u32,
        refusal_site: &'static str,
        token: &[u8],
        field_count: Option<usize>,
    ) {
        if target.is_some() {
            return;
        }
        let mut sanitized = [0u8; 32];
        let stored_token_length = token.len().min(sanitized.len());
        for (output, byte) in sanitized.iter_mut().zip(token.iter()) {
            *output = if byte.is_ascii_graphic() { *byte } else { b'?' };
        }
        *target = Some(Self {
            pid,
            refusal_site,
            token: sanitized,
            stored_token_length,
            original_token_length: token.len(),
            field_count,
        });
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
        begin_quarantine(
            child,
            self.kernel_identity.as_ref(),
            &self.launch,
            &mut self.stream,
            &mut self.quarantine,
        )
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
            self.kernel_identity.as_ref(),
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
    identity: Option<&KernelIdentity>,
    launch: &Gem5Launch,
    stream: &mut Option<UnixStream>,
    quarantine: &mut Option<Gem5QuarantineCustody>,
) -> Result<(), ProviderError> {
    if quarantine.is_some() {
        return Ok(());
    }
    let identity = identity.ok_or(ProviderError::Correlation(
        "gem5 quarantine omits authenticated original kernel identity",
    ))?;
    if child.id() != identity.pid {
        return Err(ProviderError::Correlation(
            "gem5 quarantine child differs from original kernel identity",
        ));
    }
    let native_pid = kernel_pid(identity.pid)?;
    let deadline = super::deadline(launch.timeout)?;
    let reaped = match observe_exit(child) {
        Ok(_) => {
            if closure::kernel_start_ticks(identity.pid)? != identity.start_ticks
                || getpgid(Some(native_pid)).map_err(std::io::Error::from)? != native_pid
            {
                return Err(ProviderError::Correlation(
                    "gem5 native kernel identity or private group changed",
                ));
            }
            // NOWAIT keeps the original leader alive or waitable here. Its PID
            // cannot be recycled between identity validation and group signal.
            kill_process_group(native_pid, Signal::KILL).map_err(std::io::Error::from)?;
            None
        }
        Err(ProviderError::Io(error))
            if error.raw_os_error() == Some(rustix::io::Errno::CHILD.raw_os_error()) =>
        {
            let status = child.try_wait()?.ok_or(ProviderError::Correlation(
                "gem5 original child wait ownership is unavailable",
            ))?;
            // A previously reaped leader no longer anchors a safe group signal.
            // Only a genuine cached Child status and complete empty census may
            // settle this case; never signal a potentially recycled group ID.
            if !group_members(identity.pid)?.is_empty() {
                return Err(ProviderError::Conflict(
                    "gem5 reaped leader still has unresolved private group members",
                ));
            }
            Some(status)
        }
        Err(error) => return Err(error),
    };
    *quarantine = Some(Gem5QuarantineCustody {
        pid: identity.pid,
        start_ticks: identity.start_ticks.clone(),
        deadline,
        reaped,
        proof: None,
        census_diagnostic: None,
    });
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
        let members = group_members_with_diagnostic(state.pid, &mut state.census_diagnostic)?;
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
        } else if state.deadline.is_expired() {
            return Err(ProviderError::Conflict(
                "gem5 private group reclamation deadline expired",
            ));
        }
    }
    Ok(state.proof.as_ref())
}

fn group_members(group: u32) -> Result<Vec<u32>, ProviderError> {
    group_members_with_diagnostic(group, &mut None)
}

fn group_members_with_diagnostic(
    group: u32,
    diagnostic: &mut Option<Gem5CensusDiagnostic>,
) -> Result<Vec<u32>, ProviderError> {
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
        let pgrp = parse_census_group(pid, &bytes, diagnostic)?;
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

/// Retains only bounded field facts before returning the original refusal.
fn parse_census_group(
    pid: u32,
    bytes: &[u8],
    diagnostic: &mut Option<Gem5CensusDiagnostic>,
) -> Result<u32, ProviderError> {
    let text = std::str::from_utf8(bytes).map_err(|_| {
        Gem5CensusDiagnostic::retain_first(diagnostic, pid, "stat-encoding", &[], None);
        ProviderError::Frame("gem5 kernel process stat encoding")
    })?;
    let close = text.rfind(')').ok_or_else(|| {
        Gem5CensusDiagnostic::retain_first(diagnostic, pid, "stat-command-delimiter", &[], None);
        ProviderError::Frame("gem5 kernel process stat shape")
    })?;
    if bytes.len() > 65536 {
        Gem5CensusDiagnostic::retain_first(diagnostic, pid, "stat-byte-credit", &[], None);
        return Err(ProviderError::ResourceExhausted("gem5 kernel process stat"));
    }

    let mut fields = text[close + 1..].split_ascii_whitespace();
    let token = fields.nth(2).ok_or_else(|| {
        if diagnostic.is_none() {
            let field_count = Some(text[close + 1..].split_ascii_whitespace().count());
            Gem5CensusDiagnostic::retain_first(diagnostic, pid, "pgrp-omitted", &[], field_count);
        }
        ProviderError::Frame("gem5 kernel process group omitted")
    })?;
    token.parse::<u32>().map_err(|error| {
        let site = match error.kind() {
            std::num::IntErrorKind::PosOverflow | std::num::IntErrorKind::NegOverflow => {
                "pgrp-numeric-overflow"
            }
            std::num::IntErrorKind::Empty => "pgrp-empty",
            _ => "pgrp-nondecimal",
        };
        if diagnostic.is_none() {
            let field_count = Some(text[close + 1..].split_ascii_whitespace().count());
            Gem5CensusDiagnostic::retain_first(
                diagnostic,
                pid,
                site,
                token.as_bytes(),
                field_count,
            );
        }
        ProviderError::Frame("gem5 kernel process group invalid")
    })
}

#[cfg(test)]
#[path = "containment_tests.rs"]
mod tests;
