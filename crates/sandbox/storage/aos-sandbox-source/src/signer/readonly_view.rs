//! Shares all established Source signing purposes on one paid retained view.
//!
//! The enclosing genuine Source connection owns the actual request, peer,
//! response and clean shutdown. This private attempt retains its exact native
//! opening, complete typed result and independent name/mount bookends. No raw
//! Journal, new payer, resource vector, callback or positive cleanup token is
//! returned. Source16 is deliberately absent from the closed request enum.

use std::error::Error;
use std::path::Path;

use aos_sandbox_linux::signer_mount::{SignerMountReadbackAttemptV1, SignerMountReadbackClosedV1};

use crate::signer::SourceReadonlyReceivingContextV1;
use super::readonly_native::{SourceReadonlyNativeOriginalV1 as ReadOnlyJournalOpenOriginalsV1, SourceReadonlyNativeErrorV1};
use super::comparison::SourceFixedComparisonV1;
use crate::signer_comparison as comparison;

mod current_cut;
mod clock_bracket;
mod delete_pending;
use delete_pending::SourceDeletePendingCutOriginalsV1;
use current_cut::SourceCurrentCutOriginalsV1;

use super::*;

/// Carries already-canonical comparison DATA from the same actual request.
pub(crate) enum SourceReadonlyRequestV1<'request> {
    DeletePending { query: &'request [u8; aos_sandbox_protocol::domain_ledger::delete_root::source_current::SOURCE_DELETE_CURRENT_QUERY_BYTES_V1],
        purpose: aos_sandbox_protocol::domain_ledger::delete_root::source_current::SourceDeleteCurrentPurposeDataV3 },
    CurrentCut(&'request [u8; aos_sandbox_protocol::domain_ledger::create_storage_history::source_current::SOURCE_CURRENT_QUERY_BYTES_V1]),
    Held { project: ProjectId, challenge: SourceHoldReadbackChallengeV1 },
    HeldNames { project: ProjectId, challenge: SourceHoldReadbackChallengeV1 },
    Admission { project: ProjectId, challenge: SourceHoldReadbackChallengeV1 },
    Retirement { project: ProjectId, challenge: SourceHoldReadbackChallengeV1 },
    Reservation { client_nonce: [u8; 16], project: ProjectId, expected_digest: ObjectDigest },
    Completed { challenge: SourceHoldReadbackChallengeV1 },
    StrictGenesis {
        project: Option<ProjectId>, challenge: SourceTreeGenesisChallengeV1,
        context: Option<&'request SourceTreeGenesisIntentContextV1>,
    },
    ProjectGenesis {
        challenge: super::SourceProjectGenesisChallengeV3,
        context: &'request SourceTreeGenesisIntentContextV1,
    },
    FirstSuccessor { nonce: [u8; 16], context: &'request aos_sandbox_ledger_replay::replay::phase_records::RootFirstSourceSuccessorIntentV2 },
    Continuation { nonce: [u8; 16], context: &'request aos_sandbox_ledger_replay::replay::phase_records::RootFirstSourceSuccessorIntentV2 },
    ResourceSingle { nonce: [u8; 16], context: &'request aos_sandbox_ledger_replay::replay::phase_records::RootFirstSourceSuccessorIntentV2 },
    ResourceMixed { nonce: [u8; 16], context: &'request aos_sandbox_ledger_replay::replay::phase_records::RootFirstSourceSuccessorIntentV2 },
}

impl SourceReadonlyRequestV1<'_> {
    fn require_canonical(&self, uid: u32, generation: u64) -> Result<(), SourceSignerReadbackErrorV1> {
        if uid == 0 || generation == 0 {
            return Err(SourceHoldReadbackErrorV1::NonCanonical.into());
        }
        let valid = match self {
            Self::DeletePending { query, purpose } => aos_sandbox_protocol::domain_ledger::delete_root::source_current::SourceDeleteCurrentQueryDataV1::decode_for_purpose_v3(*query, *purpose).is_ok(),
            Self::CurrentCut(bytes) => aos_sandbox_protocol::domain_ledger::create_storage_history::source_current::SourceCurrentQueryDataV1::decode(*bytes).is_ok(),
            Self::Held { project, .. } | Self::HeldNames { project, .. }
            | Self::Admission { project, .. } | Self::Retirement { project, .. } => project.as_bytes() != &[0; 16],
            Self::Reservation { client_nonce, project, expected_digest } =>
                *client_nonce != [0; 16] && project.as_bytes() != &[0; 16]
                    && expected_digest.as_bytes() != &[0; 32],
            Self::Completed { .. } => true,
            Self::StrictGenesis { project, challenge, context } =>
                project.is_none_or(|project| project.as_bytes() != &[0; 16])
                    && project.is_some() == challenge.intent().is_some()
                    && project.is_some() == context.is_some()
                    && context.is_none_or(|context|
                        crate::signer_comparison::require_original_source_uid_data_v1(uid, context).is_ok()),
            Self::ProjectGenesis { challenge, context } =>
                context.source_uid() == uid && context.project() == challenge.project(),
            Self::FirstSuccessor { nonce, context } | Self::Continuation { nonce, context } =>
                *nonce != [0; 16] && context.source_uid() == uid
                    && !context.approval_packet().has_resource_authorization(),
            Self::ResourceSingle { nonce, context } | Self::ResourceMixed { nonce, context } =>
                *nonce != [0; 16] && context.source_uid() == uid
                    && context.approval_packet().has_resource_authorization(),
        };
        if valid { Ok(()) } else { Err(SourceHoldReadbackErrorV1::NonCanonical.into()) }
    }
}

enum Reply {
    Held(Result<[u8; SOURCE_HOLD_READBACK_BYTES_V1], SourceSignerReadbackErrorV1>),
    HeldNames(Result<[u8; SOURCE_HOLD_READBACK_BYTES_V2], SourceSignerReadbackErrorV1>),
    Admission(Result<[u8; SOURCE_PROJECT_ADMISSION_READBACK_BYTES_V1], SourceSignerReadbackErrorV1>),
    Reservation(Result<[u8; SOURCE_PROJECT_RESERVATION_READBACK_BYTES_V1], SourceSignerReadbackErrorV1>),
    Completed(Result<[u8; super::SOURCE_PROJECT_COMPLETED_TERMINAL_READBACK_BYTES_V1], SourceSignerReadbackErrorV1>),
    Genesis(Result<SourceTreeGenesisReadbackPacketV2, SourceSignerReadbackErrorV1>),
    ProjectGenesis(SourceReadonlySigningPostsV1<super::source_genesis_readback::SourceProjectGenesisReadbackPacketV4>),
    Successor(Result<[u8; super::SOURCE_FIRST_SUCCESSOR_READBACK_BYTES_V2], SourceSignerReadbackErrorV1>),
    Continuation(SourceReadonlySigningPostsV1<[u8; super::source_successor_readback::SOURCE_PROJECT_CONTINUATION_READBACK_BYTES_V3]>),
    Resource(SourceReadonlySigningPostsV1<Vec<u8>>),
}

impl Reply {
    fn failure(&self) -> Option<&SourceSignerReadbackErrorV1> {
        match self {
            Self::Held(result) => result.as_ref().err(),
            Self::HeldNames(result) => result.as_ref().err(),
            Self::Admission(result) => result.as_ref().err(),
            Self::Reservation(result) => result.as_ref().err(),
            Self::Completed(result) => result.as_ref().err(),
            Self::Genesis(result) => result.as_ref().err(),
            Self::Successor(result) => result.as_ref().err(),
            Self::ProjectGenesis(result) => result.failure(),
            Self::Continuation(result) => result.failure(),
            Self::Resource(result) => result.failure(),
        }
    }

    fn bytes(&self) -> Option<&[u8]> {
        match self {
            Self::Held(result) => result.as_ref().ok().map(|packet| packet.as_slice()),
            Self::HeldNames(result) => result.as_ref().ok().map(|packet| packet.as_slice()),
            Self::Admission(result) => result.as_ref().ok().map(|packet| packet.as_slice()),
            Self::Reservation(result) => result.as_ref().ok().map(|packet| packet.as_slice()),
            Self::Completed(result) => result.as_ref().ok().map(|packet| packet.as_slice()),
            Self::Genesis(result) => result.as_ref().ok().map(AsRef::as_ref),
            Self::Successor(result) => result.as_ref().ok().map(|packet| packet.as_slice()),
            Self::ProjectGenesis(result) => result.packet().map(AsRef::as_ref),
            Self::Continuation(result) => result.packet().map(|packet| packet.as_slice()),
            Self::Resource(result) => result.packet().map(Vec::as_slice),
        }
    }
}

#[derive(Clone, Copy)]
enum Failure {
    Canonical, Fixed, Mount(usize), MountBinding(usize), Opening, NativeDebit,
    Replay, PurposeDebit, Signature, CurrentCut, DeletePending, Name(usize), Refusal,
}

/// Holds one selected readonly attempt until the real connection disposes it.
#[must_use]
pub(crate) struct SourceReadonlyAttemptV1 {
    entered: bool,
    signer_uid: u32,
    first: Option<Failure>,
    refusal: Option<SourceSignerReadbackErrorV1>,
    canonical: Option<Result<(), SourceSignerReadbackErrorV1>>,
    fixed: Option<Result<(), JournalError>>,
    native_debit: Option<Result<(), JournalError>>,
    purpose_debit: Option<Result<(), JournalError>>,
    mounts: [SignerMountReadbackAttemptV1; 4],
    mount_results: [Option<Result<(), SignerMountReadbackClosedV1>>; 4],
    mount_bindings: [Option<Result<(), SourceSignerReadbackErrorV1>>; 4],
    opening: ReadOnlyJournalOpenOriginalsV1,
    reply: Option<Reply>,
    current_cut: Option<SourceCurrentCutOriginalsV1>,
    delete_pending: Option<Box<SourceDeletePendingCutOriginalsV1>>,
    names: [Option<Result<(), SourceReadonlyNativeErrorV1>>; 3],
}

impl SourceReadonlyAttemptV1 {
    pub(crate) fn new() -> Self {
        Self {
            entered: false, signer_uid: 0, first: None, refusal: None,
            canonical: None, fixed: None, native_debit: None, purpose_debit: None,
            mounts: [SignerMountReadbackAttemptV1::new(), SignerMountReadbackAttemptV1::new(),
                SignerMountReadbackAttemptV1::new(), SignerMountReadbackAttemptV1::new()],
            mount_results: [None, None, None, None], mount_bindings: [None, None, None, None],
            opening: ReadOnlyJournalOpenOriginalsV1::new(), reply: None, current_cut: None, delete_pending: None,
            names: [None, None, None],
        }
    }

    pub(crate) fn current_cut_fixed_obligations_v1() -> Option<(usize, usize, usize)> {
        let current = SourceCurrentCutOriginalsV1::fixed_obligations_v1()?;
        let pending = SourceDeletePendingCutOriginalsV1::fixed_obligations_v1()?;
        // These closed request variants are mutually exclusive on one actual
        // attempt. Neither purpose changes the existing Source F ceiling.
        Some((current.0.max(pending.0), current.1.max(pending.1), current.2.max(pending.2)))
    }

    /// Observes one closed purpose on the same staged and funded native view.
    ///
    /// # Errors
    /// Returns a closed marker on any canonical, admission, native, semantic,
    /// signing or independent-post failure; the actual whole cause remains owned.
    pub(crate) fn observe_once(
        &mut self,
        receiving: &mut SourceReadonlyReceivingContextV1<'_, '_>,
        request: SourceReadonlyRequestV1<'_>,
        controller_uid: u32,
        generation: u64,
        key: &SigningKey,
    ) -> Result<(), ()> {
        if self.entered {
            self.refuse();
            return Err(());
        }
        self.entered = true;
        self.canonical = Some(request.require_canonical(controller_uid, generation));
        self.failed(matches!(self.canonical, Some(Err(_))), Failure::Canonical);
        if self.first.is_some() { return Err(()); }
        self.fixed = Some(receiving.admit_fixed());
        self.failed(matches!(self.fixed, Some(Err(_))), Failure::Fixed);
        if self.first.is_some() { return Err(()); }

        if let SourceReadonlyRequestV1::CurrentCut(query) = &request {
            self.current_cut = Some(SourceCurrentCutOriginalsV1::new(**query));
            let failed = self.current_cut.as_mut().is_none_or(|current| current.begin_once().is_err());
            self.failed(failed, Failure::CurrentCut);
        }
        if let SourceReadonlyRequestV1::DeletePending { query, purpose } = &request {
            self.delete_pending = Some(Box::new(SourceDeletePendingCutOriginalsV1::new(**query, *purpose)));
            let failed = self.delete_pending.as_mut().is_none_or(|pending|
                pending.begin_once(&mut self.opening, receiving).is_err());
            self.failed(failed, Failure::DeletePending);
        }
        self.signer_uid = rustix::process::geteuid().as_raw();
        if self.first.is_none() {
            self.observe_mount(0);
            self.mount_bindings[0] = Some(match self.mounts[0].witness() {
                Some(mount) if mount.source_uid() == controller_uid => Ok(()),
                _ => Err(SourceSignerReadbackErrorV1::View),
            });
            self.failed(matches!(self.mount_bindings[0], Some(Err(_))), Failure::MountBinding(0));
        }
        if self.first.is_none() {
            if let Some(mount) = self.mounts[0].witness() {
                self.opening.prepare_captured_source_once(Path::new(SIGNER_SOURCE_VIEW),
                    PROTECTED_SOURCE_DOMAIN_JOURNAL, source_domain_journal_limits(),
                    self.signer_uid, mount.root_identity(), receiving);
                self.failed(self.opening.failure().is_some(), Failure::Opening);
            }
        }
        if self.first.is_none() {
            self.native_debit = Some(match self.opening.captured_extent() {
                Some(extent) => receiving.admit_captured_native(extent),
                None => Err(JournalError::ProtectedBoundary),
            });
            self.failed(matches!(self.native_debit, Some(Err(_))), Failure::NativeDebit);
        }
        if self.first.is_none() {
            self.opening.replay_captured_source_once(receiving);
            self.failed(self.opening.failure().is_some(), Failure::Replay);
        }
        if self.first.is_none() {
            self.purpose_debit = Some(match self.opening.readback_mut() {
                Some(readback) => readback.journal_mut().admit_source_readonly_purpose(receiving),
                None => Err(JournalError::ProtectedBoundary),
            });
            self.failed(matches!(self.purpose_debit, Some(Err(_))), Failure::PurposeDebit);
        }
        if self.first.is_none() {
            if let Some(readback) = self.opening.readback_mut() {
                match request {
                    SourceReadonlyRequestV1::DeletePending { .. } => {
                        let failed = self.delete_pending.as_mut().is_none_or(|pending|
                            pending.observe_once(readback, generation, key).is_err());
                        self.failed(failed, Failure::DeletePending);
                    }
                    SourceReadonlyRequestV1::CurrentCut(query) => {
                        let _ = query;
                        let failed = self.current_cut.as_mut().is_none_or(|current| {
                            current.observe_once(readback, receiving, generation, key).is_err()
                        });
                        self.failed(failed, Failure::CurrentCut);
                    }
                    request => self.reply = Some(Self::sign_from_view(readback, request, generation, key)),
                }
            } else {
                self.refuse();
            }
            if self.current_cut.is_none() && self.delete_pending.is_none() {
                self.failed(self.reply.as_ref().is_none_or(|reply| reply.failure().is_some()), Failure::Signature);
            }
        }
        // These are independent posts on the actual original, including after
        // replay, typed signing, or an earlier name Result already failed.
        self.post_once(0);
        if self.first.is_none() { Ok(()) } else { Err(()) }
    }

    fn sign_from_view(
        readback: &mut ReadOnlyProtectedJournal,
        request: SourceReadonlyRequestV1<'_>, generation: u64, key: &SigningKey,
    ) -> Reply {
        match request {
            SourceReadonlyRequestV1::CurrentCut(_) | SourceReadonlyRequestV1::DeletePending { .. } => Reply::Held(Err(SourceSignerReadbackErrorV1::Stale)),
            SourceReadonlyRequestV1::Held { project, challenge } => Reply::Held(
                (|| {
                    let hold = {
                        let mut view = readback.comparison_v1()?;
                        comparison::replay_source_hold(&mut view, project)?
                    };
                    // The legacy Held helper decoded this row unconditionally,
                    // even though this signature purpose does not use its value.
                    let _ = readback.source_domain_challenge_v1()?;
                    Ok(sign_fields(challenge, project, hold, generation, key))
                })(),
            ),
            SourceReadonlyRequestV1::HeldNames { project, challenge } => Reply::HeldNames((|| {
                let hold = {
                    let mut view = readback.comparison_v1()?;
                    comparison::replay_source_hold(&mut view, project)?
                };
                let row = readback.source_domain_challenge_v1()?
                    .ok_or(SourceSignerReadbackErrorV1::Stale)?;
                let names = readback.physical_names_v1()?;
                if !row.matches_current(challenge.nonce(), challenge.cut(), project, hold, names)
                    .map_err(|_| JournalError::ProtectedBoundary)?
                {
                    return Err(SourceSignerReadbackErrorV1::Stale);
                }
                Ok(sign_source_hold_readback_with_names_v2(challenge, project, hold, names, generation, key))
            })()),
            SourceReadonlyRequestV1::Admission { project, challenge } => Reply::Admission(
                readback.comparison_v1().and_then(|mut view| comparison::sign_source_project_admission_from_comparison_v1(
                    &mut view, project, challenge, generation, key))),
            SourceReadonlyRequestV1::Retirement { project, challenge } => Reply::Admission(
                readback.comparison_v1().and_then(|mut view| comparison::sign_source_project_retirement_from_comparison_v1(
                    &mut view, project, challenge, generation, key))),
            SourceReadonlyRequestV1::Reservation { client_nonce, project, expected_digest } => Reply::Reservation(
                readback.comparison_v1().and_then(|mut view| comparison::sign_source_project_reservation_from_comparison_v1(
                    &mut view, client_nonce, project, expected_digest, generation, key))),
            SourceReadonlyRequestV1::Completed { challenge } => Reply::Completed(
                readback.comparison_v1().and_then(|mut view| comparison::sign_source_project_completed_terminal_from_comparison_v1(
                    &mut view, challenge, generation, key))),
            SourceReadonlyRequestV1::StrictGenesis { project, challenge, context } => Reply::Genesis(
                readback.comparison_v1().and_then(|mut view| comparison::sign_genesis_readback_from_comparison_v2(
                    &mut view, project, challenge, context, generation, key))),
            SourceReadonlyRequestV1::ProjectGenesis { challenge, context } => Reply::ProjectGenesis(
                Self::sign_with_native_posts(readback, |view| comparison::sign_project_genesis_from_comparison_v3(
                    view, challenge, context, generation, key))),
            SourceReadonlyRequestV1::FirstSuccessor { nonce, context } => Reply::Successor(
                readback.comparison_v1().and_then(|mut view| comparison::sign_source_first_successor_from_comparison_v2(
                    &mut view, nonce, context, generation, key))),
            SourceReadonlyRequestV1::Continuation { nonce, context } => Reply::Continuation(
                Self::sign_with_native_posts(readback, |view| comparison::sign_source_project_continuation_from_comparison_v3(
                    view, nonce, context, generation, key))),
            SourceReadonlyRequestV1::ResourceSingle { nonce, context } => Reply::Resource(
                Self::sign_with_native_posts(readback, |view| comparison::sign_source_resource_successor_from_comparison(
                    view, nonce, context, generation, key, false))),
            SourceReadonlyRequestV1::ResourceMixed { nonce, context } => Reply::Resource(
                Self::sign_with_native_posts(readback, |view| comparison::sign_source_resource_successor_from_comparison(
                    view, nonce, context, generation, key, true))),
        }
    }

    // Only this private actual owner can choose a comparison and run its owed
    // native name/watermark posts. The callback receives no payer or raw owner.
    fn sign_with_native_posts<T>(
        readback: &mut ReadOnlyProtectedJournal,
        sign: impl FnOnce(&mut SourceFixedComparisonV1<'_>) -> Result<T, SourceSignerReadbackErrorV1>,
    ) -> SourceReadonlySigningPostsV1<T> {
        let mut destination = SourceReadonlySigningPostsV1::new();
        if !destination.enter_once() { return destination; }
        let names = readback.physical_names_v1();
        let sequence = readback.snapshot_sequence();
        destination.returned = Some(readback.comparison_v1().and_then(|mut view| sign(&mut view)));
        destination.names = Some(readback.check_named_currentness().map_err(Into::into));
        destination.watermark = Some(if matches!(names, Ok(names) if readback.physical_names_v1().ok() == Some(names))
            && readback.snapshot_sequence() == sequence { Ok(()) }
            else { Err(SourceSignerReadbackErrorV1::Stale) });
        destination
    }

    /// Borrows the exact signed packet after the original observation posts.
    pub(crate) fn reply_data(&self) -> Option<&[u8]> {
        if self.first.is_some() || !matches!(self.names[0], Some(Ok(())))
            || !matches!(self.mount_bindings[1], Some(Ok(())))
        {
            return None;
        }
        if let Some(pending) = self.delete_pending.as_ref() { pending.packet() }
        else if let Some(current) = self.current_cut.as_ref() { current.packet() }
        else { self.reply.as_ref()?.bytes() }
    }

    /// Retains independent name and mount posts after the actual response write.
    ///
    /// # Errors
    /// Rejects wrong order, reentry, prior failure, or a failed actual post.
    pub(crate) fn recheck_after_response_once(&mut self) -> Result<(), ()> {
        self.post_once(1);
        if self.first.is_none() { Ok(()) } else { Err(()) }
    }

    /// Retains independent name and mount posts after the actual write shutdown.
    ///
    /// # Errors
    /// Rejects wrong order, reentry, prior failure, or a failed actual post.
    pub(crate) fn recheck_after_shutdown_once(&mut self) -> Result<(), ()> {
        self.post_once(2);
        if self.first.is_none() { Ok(()) } else { Err(()) }
    }

    /// Reports observation DATA; actual peer/I/O/disposal remain with its owner.
    pub(crate) fn complete_observation_positive(&self) -> bool {
        self.first.is_none() && self.reply_data().is_some()
            && self.names.iter().all(|result| matches!(result, Some(Ok(()))))
            && self.mount_bindings.iter().all(|result| matches!(result, Some(Ok(()))))
    }

    fn observe_mount(&mut self, index: usize) {
        self.mount_results[index] = Some(self.mounts[index].observe_once(
            SIGNER_SOURCE_VIEW, PROTECTED_SOURCE_DOMAIN_ROOT, self.signer_uid,
            "/run/aos", &["/var", "/var/lib", "/var/lib/aos", "/var/lib/aos/sandbox", "/run", "/run/aos"],
        ));
        self.failed(matches!(self.mount_results[index], Some(Err(_))), Failure::Mount(index));
    }

    fn post_once(&mut self, index: usize) {
        if !matches!(self.fixed, Some(Ok(()))) || self.names[index].is_some()
            || self.mount_results[index + 1].is_some()
            || index > 0 && self.mount_results[index].is_none()
        {
            self.refuse();
            return;
        }
        self.names[index] = self.opening.observe_named_currentness();
        if self.names[index].is_none() && self.first.is_none() { self.refuse(); }
        self.failed(matches!(self.names[index], Some(Err(_))), Failure::Name(index));
        self.observe_mount(index + 1);
        self.mount_bindings[index + 1] = Some(match (self.mounts[0].witness(), self.mounts[index + 1].witness()) {
            (Some(before), Some(after)) if before == after => Ok(()),
            _ => Err(SourceSignerReadbackErrorV1::View),
        });
        self.failed(matches!(self.mount_bindings[index + 1], Some(Err(_))), Failure::MountBinding(index + 1));
        if let Some(current) = self.current_cut.as_mut() {
            let failed = current.post_once(index).is_err();
            self.failed(failed, Failure::CurrentCut);
        }
        if let Some(pending) = self.delete_pending.as_mut() {
            let failed = pending.post_once(index).is_err();
            self.failed(failed, Failure::DeletePending);
        }
    }

    fn failed(&mut self, condition: bool, site: Failure) {
        if condition { self.first.get_or_insert(site); }
    }

    fn refuse(&mut self) {
        self.refusal.get_or_insert(SourceSignerReadbackErrorV1::Stale);
        self.first.get_or_insert(Failure::Refusal);
    }

    /// Borrows the exact earliest cause while every later Result remains owned.
    pub(crate) fn failure(&self) -> Option<&(dyn Error + 'static)> {
        match self.first? {
            Failure::Canonical => self.canonical.as_ref()?.as_ref().err().map(|error| error as _),
            Failure::Fixed => self.fixed.as_ref()?.as_ref().err().map(|error| error as _),
            Failure::Mount(index) => self.mounts[index].failure(),
            Failure::MountBinding(index) => self.mount_bindings[index].as_ref()?.as_ref().err().map(|error| error as _),
            Failure::Opening | Failure::Replay => self.opening.failure(),
            Failure::NativeDebit => self.native_debit.as_ref()?.as_ref().err().map(|error| error as _),
            Failure::PurposeDebit => self.purpose_debit.as_ref()?.as_ref().err().map(|error| error as _),
            Failure::Signature => {
                let cause = self.reply.as_ref()?.failure()?;
                match cause {
                    SourceSignerReadbackErrorV1::Native(SourceReadonlyNativeErrorV1::Names(index)) =>
                        self.opening.named_receiving_failure(*index).map(|error| error as _).or(Some(cause)),
                    _ => Some(cause),
                }
            }
            Failure::Name(index) => {
                let cause = self.names[index].as_ref()?.as_ref().err()?;
                match cause {
                    SourceReadonlyNativeErrorV1::Names(stage) =>
                        self.opening.named_receiving_failure(*stage).map(|error| error as _).or(Some(cause)),
                    _ => Some(cause),
                }
            }
            Failure::CurrentCut => self.current_cut.as_ref()?.failure(),
            Failure::DeletePending => self.delete_pending.as_ref()?.failure(),
            Failure::Refusal => self.refusal.as_ref().map(|error| error as _),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn later_independent_name_errors_keep_the_primary_signature_cause_resident() {
        let mut attempt = SourceReadonlyAttemptV1::new();
        attempt.reply = Some(Reply::Held(Err(SourceSignerReadbackErrorV1::Journal(
            JournalError::LimitExceeded("retained signing fixture"),
        ))));
        attempt.first = Some(Failure::Signature);
        let primary = attempt.failure().unwrap()
            .downcast_ref::<SourceSignerReadbackErrorV1>().unwrap()
            as *const SourceSignerReadbackErrorV1;
        attempt.names[0] = Some(Err(SourceReadonlyNativeErrorV1::Names(3)));
        attempt.names[1] = Some(Err(JournalError::ProtectedBoundary.into()));

        // An unpaid observer is refused, while every reached actual cause and
        // the original first-cause projection remain present in this attempt.
        assert!(attempt.recheck_after_shutdown_once().is_err());

        assert_eq!(attempt.failure().unwrap()
            .downcast_ref::<SourceSignerReadbackErrorV1>().unwrap()
            as *const SourceSignerReadbackErrorV1, primary);
        assert!(matches!(attempt.names[0], Some(Err(SourceReadonlyNativeErrorV1::Names(3)))));
        assert!(matches!(attempt.names[1], Some(Err(SourceReadonlyNativeErrorV1::Journal(JournalError::ProtectedBoundary)))));
        assert!(attempt.reply_data().is_none());
        assert!(!attempt.complete_observation_positive());
    }
}
