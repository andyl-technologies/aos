//! Source-only attestation from the signer's read-only protected journal view.
//!
//! The Controller remains the journal writer. The signer validates the fixed
//! idmapped mount, replays the exact journal and typed hierarchy head, signs a
//! caller challenge, then rechecks the retained names and mount. The packet is
//! diagnostic until an ordered all-owner handoff binds it to Root's cut.

use std::path::Path;

use aos_sandbox_core::{ObjectDigest, ProjectId};
use ed25519_dalek::SigningKey;
use thiserror::Error;

use crate::cache_residency::signer_mount::{SignerMountWitness, require_signer_mount};
use crate::hierarchy::protected_journal::replay_project_ancestry_head_v1;
use crate::journal::{
    Journal, JournalError, ProtectedJournalNamesV1, ReadOnlyProtectedJournal,
    RecoveryReport, SourceDomainPolicyHoldV1,
};
use crate::journal::{
    replay_source_domain_challenge_v1, replay_source_project_admission_challenge_v1,
};
use crate::lifecycle::protected_journal_join::{
    PROTECTED_SOURCE_DOMAIN_JOURNAL, PROTECTED_SOURCE_DOMAIN_ROOT, source_domain_journal_limits,
};

use super::source_genesis_readback::{
    SOURCE_TREE_GENESIS_READBACK_BYTES_V1, SourceTreeGenesisChallengeV1,
    SourceTreeGenesisIntentContextV1, SourceTreeGenesisReadbackPacketV2,
    sign_source_tree_genesis_fields_v2,
};
use super::source_hold_readback::{
    SOURCE_HOLD_READBACK_BYTES_V1, SourceHoldReadbackChallengeV1, SourceHoldReadbackErrorV1,
    sign_fields,
};
use super::source_hold_readback_v2::{
    SOURCE_HOLD_READBACK_BYTES_V2, sign_source_hold_readback_with_names_v2,
};
use super::source_project_admission_readback::{
    SOURCE_PROJECT_ADMISSION_READBACK_BYTES_V1, SOURCE_PROJECT_RESERVATION_READBACK_BYTES_V1,
    sign_source_project_admission_fields_v1, sign_source_project_reservation_fields_v1,
};

const SIGNER_SOURCE_VIEW: &str = "/run/aos/sandbox-source-signer-journal";

#[cfg(target_os = "linux")]
enum CurrentNixNativeObservationV1 {
    Legacy([u8; super::source_successor_readback::SOURCE_FIRST_SUCCESSOR_READBACK_BYTES_V2]),
    Resource(Vec<u8>),
}

#[cfg(target_os = "linux")]
impl CurrentNixNativeObservationV1 {
    fn bytes(&self) -> &[u8] {
        match self {
            Self::Legacy(bytes) => bytes,
            Self::Resource(bytes) => bytes,
        }
    }
}

#[cfg(target_os = "linux")]
#[derive(Clone, Copy)]
enum CurrentNixSourceFailureSiteV1 {
    Refusal, Context, InitialClock, InitialPair, Cut, Native, NativeNamePost,
    NativeWatermarkPost, Preparation, SignatureClock, SignaturePair,
    SignatureNamePost, SignatureWatermarkPost, Mount, MountBinding, View,
    ViewNamePost, ViewMountPost, ViewMountBinding, FinalClock, FinalPair,
    ResponseNamePost, ResponseWatermarkPost, ResponseMountPost, ResponseMountBinding,
}

/// Retains the complete Source16 observation attempt and its original causes.
///
/// This inert destination must precede the reader call. Every entered native,
/// preparation and clock Result stays resident through independent posts,
/// including failure. Neither a reply nor this owner issues currentness or a
/// resource-bank loan. The actual service retains it through send/EOF debt.
#[cfg(target_os = "linux")]
pub struct CurrentNixSourceObservationAttemptV1 {
    entered: bool,
    first: Option<CurrentNixSourceFailureSiteV1>,
    refusal: Option<super::CurrentNixPreflightDataErrorV1>,
    context: Option<Result<(), super::CurrentNixPreflightDataErrorV1>>,
    initial_clock: Option<Result<aos_sandbox_core::ownership_lease::RawPairedClockSample, crate::hierarchy::genesis_profile::SourceGenesisErrorV1>>,
    initial_pair: Option<Result<(), super::CurrentNixPreflightDataErrorV1>>,
    cut: Option<Result<(), super::CurrentNixPreflightDataErrorV1>>,
    native: Option<Result<CurrentNixNativeObservationV1, SourceSignerReadbackErrorV1>>,
    native_name_post: Option<Result<(), JournalError>>,
    native_watermark_post: Option<Result<(), super::CurrentNixPreflightDataErrorV1>>,
    preparation: Option<Result<Vec<u8>, super::CurrentNixPreflightDataErrorV1>>,
    message: [u8; super::nix_current_preflight::SOURCE_SIGNATURE_DOMAIN.len() + super::CURRENT_NIX_SOURCE_RESOURCE_REPLY_BYTES_V1 - 64],
    message_len: usize,
    signature_clock: Option<Result<aos_sandbox_core::ownership_lease::RawPairedClockSample, crate::hierarchy::genesis_profile::SourceGenesisErrorV1>>,
    signature_pair: Option<Result<(), super::CurrentNixPreflightDataErrorV1>>,
    signature: Option<ed25519_dalek::Signature>,
    signature_name_post: Option<Result<(), JournalError>>,
    signature_watermark_post: Option<Result<(), super::CurrentNixPreflightDataErrorV1>>,
    signer_uid: u32,
    mount: Option<Result<SignerMountWitness, std::io::Error>>,
    mount_binding: Option<Result<(), super::CurrentNixPreflightDataErrorV1>>,
    view: Option<Result<(ReadOnlyProtectedJournal, RecoveryReport), JournalError>>,
    view_name_post: Option<Result<(), JournalError>>,
    view_mount_post: Option<Result<SignerMountWitness, std::io::Error>>,
    view_mount_binding: Option<Result<(), super::CurrentNixPreflightDataErrorV1>>,
    final_clock: Option<Result<aos_sandbox_core::ownership_lease::RawPairedClockSample, crate::hierarchy::genesis_profile::SourceGenesisErrorV1>>,
    final_pair: Option<Result<(), super::CurrentNixPreflightDataErrorV1>>,
    response_name_post: Option<Result<(), JournalError>>,
    response_watermark_post: Option<Result<(), super::CurrentNixPreflightDataErrorV1>>,
    response_mount_post: Option<Result<SignerMountWitness, std::io::Error>>,
    response_mount_binding: Option<Result<(), super::CurrentNixPreflightDataErrorV1>>,
}

#[cfg(target_os = "linux")]
impl CurrentNixSourceObservationAttemptV1 {
    /// Prearms empty fixed slots without opening, observing or signing anything.
    pub const fn empty() -> Self {
        Self {
            entered: false, first: None, refusal: None, context: None,
            initial_clock: None, initial_pair: None, cut: None, native: None,
            native_name_post: None, native_watermark_post: None, preparation: None,
            message: [0; super::nix_current_preflight::SOURCE_SIGNATURE_DOMAIN.len() + super::CURRENT_NIX_SOURCE_RESOURCE_REPLY_BYTES_V1 - 64],
            message_len: 0, signature_clock: None, signature_pair: None,
            signature: None, signature_name_post: None, signature_watermark_post: None,
            signer_uid: 0, mount: None, mount_binding: None, view: None,
            view_name_post: None, view_mount_post: None, view_mount_binding: None,
            final_clock: None, final_pair: None,
            response_name_post: None, response_watermark_post: None,
            response_mount_post: None, response_mount_binding: None,
        }
    }

    /// Borrows the complete reply DATA only when every entered post succeeded.
    pub fn reply_data(&self) -> Option<&[u8]> {
        if self.first.is_some() || self.signature.is_none() {
            return None;
        }
        self.preparation.as_ref().and_then(|r| r.as_ref().ok()).map(Vec::as_slice)
    }

    /// Borrows the actual earliest typed failure without cloning or replacing it.
    pub fn failure(&self) -> Option<&(dyn std::error::Error + 'static)> {
        use CurrentNixSourceFailureSiteV1 as Site;
        match self.first? {
            Site::Refusal => self.refusal.as_ref().map(|e| e as _),
            Site::Context => self.context.as_ref()?.as_ref().err().map(|e| e as _),
            Site::InitialClock => self.initial_clock.as_ref()?.as_ref().err().map(|e| e as _),
            Site::InitialPair => self.initial_pair.as_ref()?.as_ref().err().map(|e| e as _),
            Site::Cut => self.cut.as_ref()?.as_ref().err().map(|e| e as _),
            Site::Native => self.native.as_ref()?.as_ref().err().map(|e| e as _),
            Site::NativeNamePost => self.native_name_post.as_ref()?.as_ref().err().map(|e| e as _),
            Site::NativeWatermarkPost => self.native_watermark_post.as_ref()?.as_ref().err().map(|e| e as _),
            Site::Preparation => self.preparation.as_ref()?.as_ref().err().map(|e| e as _),
            Site::SignatureClock => self.signature_clock.as_ref()?.as_ref().err().map(|e| e as _),
            Site::SignaturePair => self.signature_pair.as_ref()?.as_ref().err().map(|e| e as _),
            Site::SignatureNamePost => self.signature_name_post.as_ref()?.as_ref().err().map(|e| e as _),
            Site::SignatureWatermarkPost => self.signature_watermark_post.as_ref()?.as_ref().err().map(|e| e as _),
            Site::Mount => self.mount.as_ref()?.as_ref().err().map(|e| e as _),
            Site::MountBinding => self.mount_binding.as_ref()?.as_ref().err().map(|e| e as _),
            Site::View => self.view.as_ref()?.as_ref().err().map(|e| e as _),
            Site::ViewNamePost => self.view_name_post.as_ref()?.as_ref().err().map(|e| e as _),
            Site::ViewMountPost => self.view_mount_post.as_ref()?.as_ref().err().map(|e| e as _),
            Site::ViewMountBinding => self.view_mount_binding.as_ref()?.as_ref().err().map(|e| e as _),
            Site::FinalClock => self.final_clock.as_ref()?.as_ref().err().map(|e| e as _),
            Site::FinalPair => self.final_pair.as_ref()?.as_ref().err().map(|e| e as _),
            Site::ResponseNamePost => self.response_name_post.as_ref()?.as_ref().err().map(|e| e as _),
            Site::ResponseWatermarkPost => self.response_watermark_post.as_ref()?.as_ref().err().map(|e| e as _),
            Site::ResponseMountPost => self.response_mount_post.as_ref()?.as_ref().err().map(|e| e as _),
            Site::ResponseMountBinding => self.response_mount_binding.as_ref()?.as_ref().err().map(|e| e as _),
        }
    }

    /// Parks independent posts on the same reader after the actual response attempt.
    ///
    /// This runs after either send outcome, before the service's final raw clock.
    /// It neither replays the journal nor opens a replacement view.
    ///
    /// # Errors
    /// Returns a marker for reused post slots or changed names, watermark or mount.
    /// Every reached native Result remains in this original observation owner.
    pub fn recheck_after_response_v1(
        &mut self,
        context: &super::CurrentNixPreflightContextV1,
    ) -> Result<(), ()> {
        use CurrentNixSourceFailureSiteV1 as Site;
        use super::CurrentNixPreflightDataErrorV1 as DataError;
        if self.response_mount_post.is_some() {
            self.refusal = Some(DataError::Repeated);
            self.failed(true, Site::Refusal);
            return Err(());
        }
        if let Some(Ok((reader, _))) = self.view.as_mut() {
            self.response_name_post = Some(reader.check_named_currentness());
            self.response_watermark_post = Some(
                if reader.journal_mut().snapshot_sequence() == context.source_sequence_data() {
                    Ok(())
                } else { Err(DataError::Changed) },
            );
        }
        self.failed(matches!(self.response_name_post, Some(Err(_))), Site::ResponseNamePost);
        self.failed(matches!(self.response_watermark_post, Some(Err(_))), Site::ResponseWatermarkPost);
        self.response_mount_post = Some(require_signer_mount(
            SIGNER_SOURCE_VIEW, PROTECTED_SOURCE_DOMAIN_ROOT, self.signer_uid,
        ));
        self.failed(matches!(self.response_mount_post, Some(Err(_))), Site::ResponseMountPost);
        self.response_mount_binding = Some(match (&self.mount, &self.response_mount_post) {
            (Some(Ok(original)), Some(Ok(later))) if original == later => Ok(()),
            _ => Err(DataError::Changed),
        });
        self.failed(matches!(self.response_mount_binding, Some(Err(_))), Site::ResponseMountBinding);
        if self.first.is_some() { Err(()) } else { Ok(()) }
    }

    fn failed(&mut self, failed: bool, site: CurrentNixSourceFailureSiteV1) {
        if failed && self.first.is_none() {
            self.first = Some(site);
        }
    }

    fn prepare_reply(
        &mut self, context: &super::CurrentNixPreflightContextV1,
    ) -> Result<Vec<u8>, super::CurrentNixPreflightDataErrorV1> {
        let native = self.native.as_ref().and_then(|r| r.as_ref().ok())
            .ok_or(super::CurrentNixPreflightDataErrorV1::Changed)?.bytes();
        let complete = 8 + super::CURRENT_NIX_PREFLIGHT_CONTEXT_BYTES_V1 + 4 + native.len() + 64;
        if !matches!(complete, 3140 | 3316 | 3492) {
            return Err(super::CurrentNixPreflightDataErrorV1::Changed);
        }
        let mut reply = Vec::new();
        reply.try_reserve_exact(complete)?;
        reply.extend_from_slice(super::nix_current_preflight::SOURCE_REPLY_MAGIC);
        reply.extend_from_slice(context.bytes());
        reply.extend_from_slice(&(native.len() as u32).to_be_bytes());
        reply.extend_from_slice(native);
        let domain = super::nix_current_preflight::SOURCE_SIGNATURE_DOMAIN;
        self.message[..domain.len()].copy_from_slice(domain);
        self.message[domain.len()..domain.len() + reply.len()].copy_from_slice(&reply);
        self.message_len = domain.len() + reply.len();
        Ok(reply)
    }
}

/// Captures the distinct current-Nix Source purpose on the same fixed reader.
///
/// All preimage allocation precedes the final signature clock; the same signing
/// primitive runs immediately after its pure pair comparison. The native inner
/// successor packet supplies historical provenance only. Its actual full-family
/// reader is reused, never rebranded as a current-Nix or paid owner.
///
/// # Errors
/// Returns a marker on repeated entry, foreign original context, failed native
/// view/replay/signature preparation or independent name/watermark/clock debt.
/// The actual typed earliest error remains in `attempt`, including on `Err`.
#[cfg(target_os = "linux")]
pub fn observe_fixed_current_nix_source_into_v1(
    attempt: &mut CurrentNixSourceObservationAttemptV1,
    expected_controller_uid: u32,
    context: &super::CurrentNixPreflightContextV1,
    original: &super::RootFirstSourceSuccessorIntentV2,
    signer_generation: u64,
    signing_key: &SigningKey,
) -> Result<(), ()> {
    use CurrentNixSourceFailureSiteV1 as Site;
    use super::CurrentNixPreflightDataErrorV1 as DataError;
    if attempt.entered {
        attempt.refusal = Some(DataError::Repeated);
        attempt.failed(true, Site::Refusal);
        return Err(());
    }
    attempt.entered = true;
    attempt.context = Some(if expected_controller_uid != 0
        && expected_controller_uid == original.source_uid()
        && signer_generation != 0
        && context.project_data() == original.project()
        && matches!(context.recipe_data(), 3 | 4) == original.approval_packet().has_resource_authorization()
    { Ok(()) } else { Err(DataError::Changed) });
    attempt.failed(matches!(attempt.context, Some(Err(_))), Site::Context);

    attempt.initial_clock = Some(super::observe_root_first_source_successor_clock_v2(None));
    attempt.failed(matches!(attempt.initial_clock, Some(Err(_))), Site::InitialClock);
    if let Some(Ok(native)) = attempt.initial_clock.as_ref() {
        attempt.initial_pair = Some(context.require_original_kernel_sample_data_v1(*native));
        attempt.failed(matches!(attempt.initial_pair, Some(Err(_))), Site::InitialPair);
    }
    if attempt.first.is_none() {
        attempt.signer_uid = rustix::process::geteuid().as_raw();
        attempt.mount = Some(require_signer_mount(
            SIGNER_SOURCE_VIEW, PROTECTED_SOURCE_DOMAIN_ROOT, attempt.signer_uid,
        ));
        attempt.failed(matches!(attempt.mount, Some(Err(_))), Site::Mount);
        attempt.mount_binding = Some(match attempt.mount.as_ref() {
            Some(Ok(mount)) if mount.source_uid() == expected_controller_uid => Ok(()),
            _ => Err(DataError::Changed),
        });
        attempt.failed(matches!(attempt.mount_binding, Some(Err(_))), Site::MountBinding);
        // Park the complete open/replay Result before borrowing its reader.
        // Its original reader and recovery report move infallibly into the
        // destination after the independent posts, including on failure.
        let mut view = if attempt.first.is_none() {
            attempt.mount.as_ref().and_then(|r| r.as_ref().ok()).map(|mount| {
                open_source_signer_bound_readback(attempt.signer_uid, *mount)
            })
        } else { None };
        attempt.failed(matches!(view, Some(Err(_))), Site::View);
        if let Some(Ok((readback, _))) = view.as_mut() {
            let sequence = readback.journal_mut().snapshot_sequence();
            let names = readback.physical_names_v1();
            attempt.cut = Some(if sequence == context.source_sequence_data()
                && names == original.source_names()
            { Ok(()) } else { Err(DataError::Changed) });
            attempt.failed(matches!(attempt.cut, Some(Err(_))), Site::Cut);
            let nonce = context.root_nonce_data();
            if attempt.first.is_none() {
                attempt.native = Some(match context.recipe_data() {
                1 => super::source_successor_readback::sign_source_first_successor_from_view_v2(
                    readback, nonce, original, signer_generation, signing_key,
                ).map(CurrentNixNativeObservationV1::Legacy),
                2 => super::source_successor_readback::sign_source_project_continuation_from_view_v3(
                    readback, nonce, original, signer_generation, signing_key,
                ).map(CurrentNixNativeObservationV1::Legacy),
                3 | 4 => super::source_successor_readback::sign_source_resource_successor_from_view(
                    readback, nonce, original, signer_generation, signing_key,
                    context.recipe_data() == 4,
                ).map(CurrentNixNativeObservationV1::Resource),
                _ => Err(SourceSignerReadbackErrorV1::Stale),
                });
                attempt.failed(matches!(attempt.native, Some(Err(_))), Site::Native);
            }
            attempt.native_name_post = Some(readback.check_named_currentness());
            attempt.failed(matches!(attempt.native_name_post, Some(Err(_))), Site::NativeNamePost);
            attempt.native_watermark_post = Some(if readback.journal_mut().snapshot_sequence() == sequence {
                Ok(())
            } else { Err(DataError::Changed) });
            attempt.failed(matches!(attempt.native_watermark_post, Some(Err(_))), Site::NativeWatermarkPost);

            if attempt.first.is_none() {
                let preparation = attempt.prepare_reply(context);
                attempt.preparation = Some(preparation);
                attempt.failed(matches!(attempt.preparation, Some(Err(_))), Site::Preparation);
            }
            if attempt.first.is_none() {
                attempt.signature_clock = Some(super::observe_root_first_source_successor_clock_v2(None));
                attempt.failed(matches!(attempt.signature_clock, Some(Err(_))), Site::SignatureClock);
                if let Some(Ok(native)) = attempt.signature_clock.as_ref() {
                    attempt.signature_pair = Some(context.require_original_kernel_sample_data_v1(*native));
                    attempt.failed(matches!(attempt.signature_pair, Some(Err(_))), Site::SignaturePair);
                }
                if attempt.first.is_none() {
                    use ed25519_dalek::Signer as _;
                    attempt.signature = Some(signing_key.sign(&attempt.message[..attempt.message_len]));
                    if let (Some(Ok(reply)), Some(signature)) = (&mut attempt.preparation, &attempt.signature) {
                        // Exact complete capacity was reserved before the clock.
                        reply.extend_from_slice(&signature.to_bytes());
                    }
                }
            }
            attempt.signature_name_post = Some(readback.check_named_currentness());
            attempt.failed(matches!(attempt.signature_name_post, Some(Err(_))), Site::SignatureNamePost);
            attempt.signature_watermark_post = Some(if readback.journal_mut().snapshot_sequence() == sequence {
                Ok(())
            } else { Err(DataError::Changed) });
            attempt.failed(matches!(attempt.signature_watermark_post, Some(Err(_))), Site::SignatureWatermarkPost);
            attempt.view_name_post = Some(readback.check_named_currentness());
            attempt.failed(matches!(attempt.view_name_post, Some(Err(_))), Site::ViewNamePost);
        }
        attempt.view_mount_post = Some(require_signer_mount(
            SIGNER_SOURCE_VIEW, PROTECTED_SOURCE_DOMAIN_ROOT, attempt.signer_uid,
        ));
        attempt.failed(matches!(attempt.view_mount_post, Some(Err(_))), Site::ViewMountPost);
        attempt.view_mount_binding = Some(match (&attempt.mount, &attempt.view_mount_post) {
            (Some(Ok(original)), Some(Ok(later))) if original == later => Ok(()),
            _ => Err(DataError::Changed),
        });
        attempt.failed(matches!(attempt.view_mount_binding, Some(Err(_))), Site::ViewMountBinding);
        attempt.view = view;
    }

    attempt.final_clock = Some(super::observe_root_first_source_successor_clock_v2(None));
    attempt.failed(matches!(attempt.final_clock, Some(Err(_))), Site::FinalClock);
    if let Some(Ok(native)) = attempt.final_clock.as_ref() {
        attempt.final_pair = Some(context.require_original_kernel_sample_data_v1(*native));
        attempt.failed(matches!(attempt.final_pair, Some(Err(_))), Site::FinalPair);
    }
    if attempt.first.is_some() { Err(()) } else { Ok(()) }
}

/// Signs actual first-successor DATA through the existing fixed Source reader.
///
/// # Errors
/// Rejects unsafe view/name custody, a foreign original context, noncanonical
/// challenge, incomplete native replay or changed cut. The request context is
/// comparison DATA, never Root authority; the signer retains its existing key.
#[cfg(target_os = "linux")]
pub fn sign_fixed_source_first_successor_readback_v2(
    expected_controller_uid: u32, fresh_nonce: [u8; 16],
    context: &super::RootFirstSourceSuccessorIntentV2,
    signer_generation: u64, signing_key: &SigningKey,
) -> Result<[u8; super::source_successor_readback::SOURCE_FIRST_SUCCESSOR_READBACK_BYTES_V2], SourceSignerReadbackErrorV1> {
    if expected_controller_uid == 0 || expected_controller_uid != context.source_uid()
        || signer_generation == 0 || fresh_nonce == [0; 16]
        || context.approval_packet().has_resource_authorization()
    {
        return Err(SourceHoldReadbackErrorV1::NonCanonical.into());
    }
    with_source_signer_journal_view(expected_controller_uid, |readback| {
        super::source_successor_readback::sign_source_first_successor_from_view_v2(
            readback, fresh_nonce, context, signer_generation, signing_key,
        )
    })
}

/// Signs explicit mixed-project DATA through the same fixed Source reader.
///
/// # Errors
/// Rejects foreign privileged UID, invalid challenge, unsafe reader custody,
/// incomplete full-family replay or a changed actual selected project cut.
/// This does not authenticate fresh Controller admission or Root authority.
#[cfg(target_os = "linux")]
pub fn sign_fixed_source_project_continuation_readback_v3(
    expected_controller_uid: u32, fresh_nonce: [u8; 16],
    context: &super::RootFirstSourceSuccessorIntentV2,
    signer_generation: u64, signing_key: &SigningKey,
) -> Result<[u8; super::source_successor_readback::SOURCE_PROJECT_CONTINUATION_READBACK_BYTES_V3], SourceSignerReadbackErrorV1> {
    if expected_controller_uid == 0 || expected_controller_uid != context.source_uid()
        || signer_generation == 0 || fresh_nonce == [0; 16]
        || context.approval_packet().has_resource_authorization()
    {
        return Err(SourceHoldReadbackErrorV1::NonCanonical.into());
    }
    with_source_signer_journal_view(expected_controller_uid, |readback| {
        let sequence = readback.journal_mut().snapshot_sequence();
        let returned = super::source_successor_readback::sign_source_project_continuation_from_view_v3(
            readback, fresh_nonce, context, signer_generation, signing_key,
        );
        let name_post = readback.check_named_currentness().map_err(SourceSignerReadbackErrorV1::from);
        let watermark_post = if readback.journal_mut().snapshot_sequence() == sequence {
            Ok(())
        } else {
            Err(SourceSignerReadbackErrorV1::Stale)
        };
        // Retain the actual signature/native cause across the independent
        // watermark post even on error. The existing outer view helper's
        // pre-return negative-prefix release boundary is not changed here.
        match returned {
            Err(error) => Err(error),
            Ok(packet) => {
                name_post?;
                watermark_post.map(|()| packet)
            }
        }
    })
}

/// Signs a closed full-resource successor recipe through the same Source view.
///
/// The `mixed` selector chooses comparison framing only; it supplies no Root,
/// Controller, currentness or resource-bank authority.
///
/// # Errors
/// Rejects legacy context, unsafe fixed-view custody, foreign UID, malformed
/// challenge, incomplete full-family replay or independent post debt.
#[cfg(target_os = "linux")]
pub fn sign_fixed_source_resource_successor_readback_v4(
    expected_controller_uid: u32, fresh_nonce: [u8; 16],
    context: &super::RootFirstSourceSuccessorIntentV2,
    signer_generation: u64, signing_key: &SigningKey, mixed: bool,
) -> Result<Vec<u8>, SourceSignerReadbackErrorV1> {
    if expected_controller_uid == 0 || expected_controller_uid != context.source_uid()
        || signer_generation == 0 || fresh_nonce == [0; 16]
        || !context.approval_packet().has_resource_authorization()
    {
        return Err(SourceHoldReadbackErrorV1::NonCanonical.into());
    }
    with_source_signer_journal_view(expected_controller_uid, |readback| {
        let sequence = readback.journal_mut().snapshot_sequence();
        let returned = super::source_successor_readback::sign_source_resource_successor_from_view(
            readback, fresh_nonce, context, signer_generation, signing_key, mixed,
        );
        let name_post = readback.check_named_currentness().map_err(SourceSignerReadbackErrorV1::from);
        let watermark_post = if readback.journal_mut().snapshot_sequence() == sequence {
            Ok(())
        } else {
            Err(SourceSignerReadbackErrorV1::Stale)
        };
        match returned {
            Err(error) => Err(error),
            Ok(packet) => {
                name_post?;
                watermark_post.map(|()| packet)
            }
        }
    })
}

/// Observes initial materialization only through the existing fixed reader view.
///
/// Empty is joined absence of every Source journal row, never a
/// project lookup miss. Prepared/Anchored require the exact original intent.
/// The V2 request supplies comparison data only; the signed observation remains
/// V1. Actual pending rows or ACK commitments, not a fresh nonce, bind replay.
/// This Source-purpose signature does not authenticate Root sender authority,
/// a current Root floor, or a Controller-retained writer.
///
/// # Errors
///
/// Rejects unsafe view/owner/names, malformed or legacy materialization, a
/// missing or substituted intent/project, mixed ACK state or changed replay.
pub fn sign_fixed_source_tree_genesis_readback_v2(
    expected_controller_uid: u32,
    project: Option<ProjectId>,
    challenge: SourceTreeGenesisChallengeV1,
    intent_context: Option<&SourceTreeGenesisIntentContextV1>,
    signer_generation: u64,
    signing_key: &SigningKey,
) -> Result<[u8; SOURCE_TREE_GENESIS_READBACK_BYTES_V1], SourceSignerReadbackErrorV1> {
    if intent_context.is_some_and(SourceTreeGenesisIntentContextV1::has_resource_authorization) {
        return Err(SourceHoldReadbackErrorV1::NonCanonical.into());
    }
    sign_fixed_source_tree_genesis_readback_v3(
        expected_controller_uid, project, challenge, intent_context, signer_generation, signing_key,
    )?.into_legacy().map_err(Into::into)
}

/// Signs the exact legacy or resource strict observation on the same fixed view.
///
/// This version retains the complete signed authorization and original receipt.
/// It does not supply Root, Controller or current administrative authority.
///
/// # Errors
/// Rejects mixed project/context/intent, unsafe reader custody, malformed full
/// replay, foreign original joins or a changed actual Source cut.
pub fn sign_fixed_source_tree_genesis_readback_v3(
    expected_controller_uid: u32,
    project: Option<ProjectId>,
    challenge: SourceTreeGenesisChallengeV1,
    intent_context: Option<&SourceTreeGenesisIntentContextV1>,
    signer_generation: u64,
    signing_key: &SigningKey,
) -> Result<SourceTreeGenesisReadbackPacketV2, SourceSignerReadbackErrorV1> {
    if expected_controller_uid == 0
        || signer_generation == 0
        || project.is_some_and(|project| project.as_bytes() == &[0; 16])
        || project.is_some() != challenge.intent().is_some()
        || project.is_some() != intent_context.is_some()
        || intent_context.is_some_and(|context| context.source_uid() != expected_controller_uid)
    {
        return Err(SourceHoldReadbackErrorV1::NonCanonical.into());
    }
    with_source_signer_journal_view(expected_controller_uid, |readback| {
        sign_genesis_readback_from_view_v2(
            readback,
            project,
            challenge,
            intent_context,
            signer_generation,
            signing_key,
        )
    })
}

/// Signs the selected approval-free genesis purpose from the same fixed reader.
///
/// # Errors
/// Rejects substituted UID/context, malformed challenge, incomplete foreign
/// families, a foreign pending project, changed names or watermark, and signing.
/// The context is comparison DATA; genuine Root and Controller admission is separate.
#[cfg(target_os = "linux")]
pub fn sign_fixed_source_project_genesis_readback_v3(
    expected_controller_uid: u32,
    challenge: super::source_genesis_readback::SourceProjectGenesisChallengeV3,
    context: &SourceTreeGenesisIntentContextV1,
    signer_generation: u64,
    signing_key: &SigningKey,
) -> Result<[u8; super::source_genesis_readback::SOURCE_PROJECT_GENESIS_READBACK_BYTES_V3], SourceSignerReadbackErrorV1> {
    if context.has_resource_authorization() {
        return Err(SourceHoldReadbackErrorV1::NonCanonical.into());
    }
    match sign_fixed_source_project_genesis_readback_v4(
        expected_controller_uid, challenge, context, signer_generation, signing_key,
    )? {
        super::source_genesis_readback::SourceProjectGenesisReadbackPacketV4::Legacy(packet) => Ok(packet),
        super::source_genesis_readback::SourceProjectGenesisReadbackPacketV4::Resource(_) =>
            Err(SourceHoldReadbackErrorV1::NonCanonical.into()),
    }
}

/// Signs the complete versioned Project receipt through the same fixed reader.
///
/// The existing Source key, original view, owner/name checks and independent
/// posts remain shared with the legacy entry. Context is comparison DATA only.
///
/// # Errors
/// Rejects a foreign UID/context, invalid challenge, incomplete full-family
/// replay, changed real custody or watermark, and signature failures.
#[cfg(target_os = "linux")]
pub fn sign_fixed_source_project_genesis_readback_v4(
    expected_controller_uid: u32,
    challenge: super::source_genesis_readback::SourceProjectGenesisChallengeV3,
    context: &SourceTreeGenesisIntentContextV1,
    signer_generation: u64,
    signing_key: &SigningKey,
) -> Result<super::source_genesis_readback::SourceProjectGenesisReadbackPacketV4, SourceSignerReadbackErrorV1> {
    if expected_controller_uid == 0 || context.source_uid() != expected_controller_uid
        || context.project() != challenge.project()
        || signer_generation == 0
    {
        return Err(SourceHoldReadbackErrorV1::NonCanonical.into());
    }
    with_source_signer_journal_view(expected_controller_uid, |readback| {
        let names = readback.physical_names_v1();
        let sequence = readback.journal_mut().snapshot_sequence();
        let returned = sign_project_genesis_from_view_v3(
            readback, challenge, context, signer_generation, signing_key,
        );
        let name_post = readback.check_named_currentness().map_err(SourceSignerReadbackErrorV1::from);
        let watermark_post = if readback.physical_names_v1() == names
            && readback.journal_mut().snapshot_sequence() == sequence
        { Ok(()) } else { Err(SourceSignerReadbackErrorV1::Stale) };
        // Original signing/native failure remains resident while both independent
        // posts run. The inherited outer view-helper prefix boundary is unchanged.
        match returned {
            Err(error) => Err(error),
            Ok(packet) => { name_post?; watermark_post.map(|()| packet) }
        }
    })
}

#[cfg(target_os = "linux")]
fn sign_project_genesis_from_view_v3(
    readback: &mut ReadOnlyProtectedJournal,
    challenge: super::source_genesis_readback::SourceProjectGenesisChallengeV3,
    context: &SourceTreeGenesisIntentContextV1,
    signer_generation: u64,
    signing_key: &SigningKey,
) -> Result<super::source_genesis_readback::SourceProjectGenesisReadbackPacketV4, SourceSignerReadbackErrorV1> {
    let project = challenge.project();
    let journal = readback.journal_mut();
    let rows = journal.source_project_genesis_data_v3(project)?.into_genesis();
    let receipt = rows.receipts.get(&project);
    if rows.receipts.is_empty()
        || receipt.map(|receipt| receipt.intent_digest()) != challenge.intent()
        || rows.pending.as_ref().is_some_and(|pending| pending.project != project)
    {
        return Err(SourceSignerReadbackErrorV1::Stale);
    }
    let instance = rows.receipts.values().next().ok_or(SourceSignerReadbackErrorV1::Stale)?.instance();
    let names = readback.physical_names_v1();
    if rows.pending.as_ref().is_some_and(|pending| pending.names != names) {
        return Err(SourceSignerReadbackErrorV1::Stale);
    }
    if let Some(receipt) = receipt {
        context.require_actual_receipt(receipt, rows.pending.as_ref())
            .map_err(|_| SourceSignerReadbackErrorV1::Stale)?;
        if let Some(ack) = rows.acks.get(&project) {
            context.require_actual_ack(receipt, ack.root_floor)
                .map_err(|_| SourceSignerReadbackErrorV1::Stale)?;
        }
    }
    let ack = rows.acks.get(&project).map(|ack| (ack.root_floor, ack.digest()));
    super::source_genesis_readback::sign_source_project_genesis_fields_v4(
        challenge, names, readback.journal_mut().snapshot_sequence(), receipt, ack,
        instance, signer_generation, signing_key, context.has_resource_authorization(),
    ).map_err(Into::into)
}

/// Reuses actual read-only replay; no fixture or supplied receipt can mint it.
pub(super) fn sign_genesis_readback_from_view(
    readback: &mut ReadOnlyProtectedJournal,
    project: Option<ProjectId>,
    challenge: SourceTreeGenesisChallengeV1,
    intent_context: Option<&SourceTreeGenesisIntentContextV1>,
    signer_generation: u64,
    signing_key: &SigningKey,
) -> Result<[u8; SOURCE_TREE_GENESIS_READBACK_BYTES_V1], SourceSignerReadbackErrorV1> {
    if intent_context.is_some_and(SourceTreeGenesisIntentContextV1::has_resource_authorization) {
        return Err(SourceHoldReadbackErrorV1::NonCanonical.into());
    }
    sign_genesis_readback_from_view_v2(
        readback, project, challenge, intent_context, signer_generation, signing_key,
    )?.into_legacy().map_err(Into::into)
}

fn sign_genesis_readback_from_view_v2(
    readback: &mut ReadOnlyProtectedJournal,
    project: Option<ProjectId>,
    challenge: SourceTreeGenesisChallengeV1,
    intent_context: Option<&SourceTreeGenesisIntentContextV1>,
    signer_generation: u64,
    signing_key: &SigningKey,
) -> Result<SourceTreeGenesisReadbackPacketV2, SourceSignerReadbackErrorV1> {
    let rows = crate::hierarchy::source_genesis::validate_actual_rows(readback.journal_mut())
        .map_err(|_| SourceSignerReadbackErrorV1::Stale)?;
    let names = readback.physical_names_v1();
    let sequence = readback.journal_mut().snapshot_sequence();
    let receipt = match project {
        Some(project) => Some(
            rows.receipts
                .get(&project)
                .ok_or(SourceSignerReadbackErrorV1::Stale)?,
        ),
        None if rows.receipts.is_empty()
            && rows.pending.is_none()
            && rows.acks.is_empty()
            && readback.journal_mut().all_records().next().is_none() =>
        {
            None
        }
        None => return Err(SourceSignerReadbackErrorV1::Stale),
    };
    if receipt.map(|receipt| receipt.intent_digest()) != challenge.intent()
        || receipt.is_some() != intent_context.is_some()
        || rows
            .pending
            .as_ref()
            .is_some_and(|pending| Some(pending.project) == project && pending.names != names)
    {
        return Err(SourceSignerReadbackErrorV1::Stale);
    }
    if let (Some(receipt), Some(context)) = (receipt, intent_context) {
        // The challenge correlates this observation only. The original nonce
        // comes from the durable pending marker and must reconstruct the exact
        // intent committed by this actual receipt, including UID and roles.
        context
            .require_actual_receipt(
                receipt,
                rows.pending
                    .as_ref()
                    .filter(|pending| pending.project == receipt.project()),
            )
            .map_err(|_| SourceSignerReadbackErrorV1::Stale)?;
        if let Some(ack) = rows.acks.get(&receipt.project()) {
            context
                .require_actual_ack(receipt, ack.root_floor)
                .map_err(|_| SourceSignerReadbackErrorV1::Stale)?;
        }
    }
    let ack = project
        .and_then(|project| rows.acks.get(&project))
        .map(|ack| (ack.root_floor, ack.digest()));
    let packet = sign_source_tree_genesis_fields_v2(
        challenge,
        names,
        sequence,
        receipt,
        ack,
        signer_generation,
        signing_key,
    )?;

    if readback.physical_names_v1() != names
        || readback.journal_mut().snapshot_sequence() != sequence
        || crate::hierarchy::source_genesis::validate_actual_rows(readback.journal_mut())
            .map_err(|_| SourceSignerReadbackErrorV1::Stale)?
            != rows
    {
        return Err(SourceSignerReadbackErrorV1::Stale);
    }
    Ok(packet)
}

/// Signs the exact unconsumed Source reservation from the independent view.
///
/// This cannot prove ancestry or replace the later AOSQPR03 admission packet.
/// Root must serialize its stage against a durable cancellation marker.
///
/// # Errors
///
/// Rejects a missing/consumed row, changed digest or physical names, unsafe
/// signer view, or invalid signer generation.
pub fn sign_fixed_source_project_reservation_readback_v1(
    expected_controller_uid: u32,
    client_nonce: [u8; 16],
    project: ProjectId,
    expected_digest: ObjectDigest,
    signer_generation: u64,
    signing_key: &SigningKey,
) -> Result<[u8; SOURCE_PROJECT_RESERVATION_READBACK_BYTES_V1], SourceSignerReadbackErrorV1> {
    if expected_controller_uid == 0
        || signer_generation == 0
        || client_nonce == [0; 16]
        || project.as_bytes() == &[0; 16]
        || expected_digest.as_bytes() == &[0; 32]
    {
        return Err(SourceHoldReadbackErrorV1::NonCanonical.into());
    }
    with_source_signer_journal_view(expected_controller_uid, |readback| {
        let row = readback
            .journal_mut()
            .source_project_admission_reservation_status_v1()?
            .and_then(|(row, canceled)| (!canceled).then_some(row))
            .ok_or(SourceSignerReadbackErrorV1::Stale)?;
        let names = readback.physical_names_v1();
        if row.client_nonce() != client_nonce
            || row.project() != project
            || row.record_digest() != expected_digest
            || row.names() != names
            || readback
                .journal_mut()
                .source_project_admission_status_v1()?
                .is_some()
        {
            return Err(SourceSignerReadbackErrorV1::Stale);
        }
        let packet =
            sign_source_project_reservation_fields_v1(row, signer_generation, signing_key)?;
        if readback
            .journal_mut()
            .source_project_admission_reservation_status_v1()?
            != Some((row, false))
            || readback
                .journal_mut()
                .source_project_admission_status_v1()?
                .is_some()
            || readback.physical_names_v1() != names
        {
            return Err(SourceSignerReadbackErrorV1::Stale);
        }
        Ok(packet)
    })
}

/// Reports a failed independent Source journal attestation.
#[derive(Debug, Error)]
pub enum SourceSignerReadbackErrorV1 {
    /// The signer view or original Source root is missing or unsafe.
    #[error("unsafe Source signer journal view")]
    View,
    /// The protected journal was malformed, stale, or replaced.
    #[error(transparent)]
    Journal(#[from] JournalError),
    /// The active hold does not match the complete typed hierarchy replay.
    #[error("Source hold and typed hierarchy head are not current")]
    Stale,
    /// The challenge or signer generation is noncanonical.
    #[error(transparent)]
    Signing(#[from] SourceHoldReadbackErrorV1),
    /// The first-successor reader retains its original typed replay cause.
    #[error(transparent)]
    FirstSuccessor(#[from] crate::hierarchy::genesis_profile::SourceGenesisErrorV1),
}

/// Signs the active Source hold after read-only fixed-name and typed replay.
///
/// `expected_controller_uid` is the on-disk Source journal owner. The signer
/// must hold only its independently provisioned Source-purpose key. This
/// observation grants no writer, Q04, Create, or effect authority.
///
/// # Errors
///
/// Rejects a missing or altered idmapped mount, wrong original owner, unsafe
/// journal or lock, incomplete tail, missing hold, stale hierarchy head, or
/// changed physical name during the signed observation.
pub fn sign_fixed_source_signer_readback_v1(
    expected_controller_uid: u32,
    project: ProjectId,
    challenge: SourceHoldReadbackChallengeV1,
    signer_generation: u64,
    signing_key: &SigningKey,
) -> Result<[u8; SOURCE_HOLD_READBACK_BYTES_V1], SourceSignerReadbackErrorV1> {
    with_current_source_signer_view(
        expected_controller_uid,
        project,
        signer_generation,
        |hold, _, _| {
            Ok(sign_fields(
                challenge,
                project,
                hold,
                signer_generation,
                signing_key,
            ))
        },
    )
}

/// Signs the held Source head and exact fixed journal/lock inode identities.
///
/// The signer still has only a read-only view. This V2 packet is
/// nonauthorizing until Root joins it to a challenge committed under the
/// matching Controller-retained Source writer and rechecks that cut.
///
/// # Errors
///
/// Rejects stale or replaced fixed names, mount, hold, ancestry, or signer
/// generation, and incomplete protected replay.
pub fn sign_fixed_source_signer_readback_v2(
    expected_controller_uid: u32,
    project: ProjectId,
    challenge: SourceHoldReadbackChallengeV1,
    signer_generation: u64,
    signing_key: &SigningKey,
) -> Result<[u8; SOURCE_HOLD_READBACK_BYTES_V2], SourceSignerReadbackErrorV1> {
    with_current_source_signer_view(
        expected_controller_uid,
        project,
        signer_generation,
        |hold, names, row| {
            let row = row.ok_or(SourceSignerReadbackErrorV1::Stale)?;
            if !row.matches_current(challenge.nonce(), challenge.cut(), project, hold, names)? {
                return Err(SourceSignerReadbackErrorV1::Stale);
            }
            Ok(sign_source_hold_readback_with_names_v2(
                challenge,
                project,
                hold,
                names,
                signer_generation,
                signing_key,
            ))
        },
    )
}

/// Signs a durable pre-Q04 project ancestry challenge from the Source-only view.
///
/// The signer replays the exact AOSQPA01 row, typed project ancestry, and
/// fixed physical names twice around signing. It never accepts a caller-
/// supplied ancestry digest or grants a project-source admission itself.
///
/// # Errors
///
/// Rejects a missing or changed mount, row, ancestry head, challenge, names,
/// owner UID, or signer generation.
pub fn sign_fixed_source_project_admission_readback_v1(
    expected_controller_uid: u32,
    project: ProjectId,
    challenge: SourceHoldReadbackChallengeV1,
    signer_generation: u64,
    signing_key: &SigningKey,
) -> Result<[u8; SOURCE_PROJECT_ADMISSION_READBACK_BYTES_V1], SourceSignerReadbackErrorV1> {
    if project.as_bytes() == &[0; 16] || signer_generation == 0 || expected_controller_uid == 0 {
        return Err(SourceHoldReadbackErrorV1::NonCanonical.into());
    }
    with_source_signer_journal_view(expected_controller_uid, |readback| {
        let row = replay_source_project_admission_challenge_v1(readback.journal_mut())?
            .ok_or(SourceSignerReadbackErrorV1::Stale)?;
        let ancestry = replay_project_ancestry_head_v1(readback.journal_mut(), project)
            .map_err(|_| SourceSignerReadbackErrorV1::Stale)?
            .ok_or(SourceSignerReadbackErrorV1::Stale)?
            .head();
        let names = readback.physical_names_v1();
        if !crate::journal::source_project_challenge_matches_current(row,
            challenge.nonce(),
            challenge.cut(),
            project,
            ancestry,
            row.stage(),
            names,
        ) {
            return Err(SourceSignerReadbackErrorV1::Stale);
        }
        let reservation = readback
            .journal_mut()
            .source_project_admission_reservation_v1()?
            .ok_or(SourceSignerReadbackErrorV1::Stale)?;
        if reservation.project() != project
            || reservation.names() != names
            || reservation.issue() != row.issue()
        {
            return Err(SourceSignerReadbackErrorV1::Stale);
        }
        let packet = sign_source_project_admission_fields_v1(
            row,
            reservation,
            signer_generation,
            signing_key,
        )?;
        let postflight = replay_source_project_admission_challenge_v1(readback.journal_mut())?;
        let current_ancestry = replay_project_ancestry_head_v1(readback.journal_mut(), project)
            .map_err(|_| SourceSignerReadbackErrorV1::Stale)?
            .ok_or(SourceSignerReadbackErrorV1::Stale)?
            .head();
        if postflight != Some(row)
            || readback
                .journal_mut()
                .source_project_admission_reservation_v1()?
                != Some(reservation)
            || current_ancestry != ancestry
        {
            return Err(SourceSignerReadbackErrorV1::Stale);
        }
        Ok(packet)
    })
}

/// Signs only the exact pending Source row for Root's nonauthorizing abort.
///
/// Unlike admission, retirement does not claim current project ancestry. Its
/// separate AOSQPR04 domain cannot satisfy Root's positive commit verifier.
///
/// # Errors
///
/// Rejects changed row, names, peer challenge, or unsafe read-only view.
pub fn sign_fixed_source_project_retirement_readback_v1(
    expected_controller_uid: u32,
    project: ProjectId,
    challenge: SourceHoldReadbackChallengeV1,
    signer_generation: u64,
    signing_key: &SigningKey,
) -> Result<[u8; SOURCE_PROJECT_ADMISSION_READBACK_BYTES_V1], SourceSignerReadbackErrorV1> {
    if project.as_bytes() == &[0; 16] || signer_generation == 0 || expected_controller_uid == 0 {
        return Err(SourceHoldReadbackErrorV1::NonCanonical.into());
    }
    with_source_signer_journal_view(expected_controller_uid, |readback| {
        let (row, settled) = readback
            .journal_mut()
            .source_project_admission_status_v1()?
            .ok_or(SourceSignerReadbackErrorV1::Stale)?;
        let names = readback.physical_names_v1();
        if settled
            || row.nonce() != challenge.nonce()
            || row.cut() != challenge.cut()
            || row.project() != project
            || row.names() != names
        {
            return Err(SourceSignerReadbackErrorV1::Stale);
        }
        let reservation = readback
            .journal_mut()
            .source_project_admission_reservation_v1()?
            .ok_or(SourceSignerReadbackErrorV1::Stale)?;
        if reservation.project() != project
            || reservation.names() != names
            || reservation.issue() != row.issue()
        {
            return Err(SourceSignerReadbackErrorV1::Stale);
        }
        let packet =
            super::source_project_admission_readback::sign_source_project_retirement_fields_v1(
                row,
                reservation,
                signer_generation,
                signing_key,
            )?;
        if readback
            .journal_mut()
            .source_project_admission_status_v1()?
            != Some((row, false))
            || readback
                .journal_mut()
                .source_project_admission_reservation_v1()?
                != Some(reservation)
            || readback.physical_names_v1() != names
        {
            return Err(SourceSignerReadbackErrorV1::Stale);
        }
        Ok(packet)
    })
}

fn with_current_source_signer_view<const N: usize>(
    expected_controller_uid: u32,
    project: ProjectId,
    signer_generation: u64,
    sign: impl FnOnce(
        SourceDomainPolicyHoldV1,
        ProtectedJournalNamesV1,
        Option<crate::journal::SourceDomainChallengeV1>,
    ) -> Result<[u8; N], SourceSignerReadbackErrorV1>,
) -> Result<[u8; N], SourceSignerReadbackErrorV1> {
    if project.as_bytes() == &[0; 16] || signer_generation == 0 || expected_controller_uid == 0 {
        return Err(SourceHoldReadbackErrorV1::NonCanonical.into());
    }
    with_source_signer_journal_view(expected_controller_uid, |readback| {
        let hold = replay_source_hold(readback, project)?;
        let row = replay_source_domain_challenge_v1(readback.journal_mut())?;
        sign(hold, readback.physical_names_v1(), row)
    })
}

pub(super) fn with_source_signer_journal_view<T>(
    expected_controller_uid: u32,
    sign: impl FnOnce(&mut ReadOnlyProtectedJournal) -> Result<T, SourceSignerReadbackErrorV1>,
) -> Result<T, SourceSignerReadbackErrorV1> {
    let signer_uid = rustix::process::geteuid().as_raw();
    let mount = require_signer_mount(SIGNER_SOURCE_VIEW, PROTECTED_SOURCE_DOMAIN_ROOT, signer_uid)
        .map_err(|_| SourceSignerReadbackErrorV1::View)?;
    if mount.source_uid() != expected_controller_uid {
        return Err(SourceSignerReadbackErrorV1::View);
    }

    let (mut readback, _) = open_source_signer_bound_readback(signer_uid, mount)?;
    let packet = sign(&mut readback)?;

    readback.check_named_currentness()?;
    if require_signer_mount(SIGNER_SOURCE_VIEW, PROTECTED_SOURCE_DOMAIN_ROOT, signer_uid)
        .map_err(|_| SourceSignerReadbackErrorV1::View)?
        != mount
    {
        return Err(SourceSignerReadbackErrorV1::View);
    }
    Ok(packet)
}

// Both callers use the same fixed bounded opening and native replay engine.
// The legacy wrapper still drops its recovery report at the original statement;
// Source16 retains the complete returned tuple through response debt instead.
fn open_source_signer_bound_readback(
    signer_uid: u32,
    mount: SignerMountWitness,
) -> Result<(ReadOnlyProtectedJournal, RecoveryReport), JournalError> {
    Journal::open_read_only_protected_at_for_uid_bound(
        Path::new(SIGNER_SOURCE_VIEW),
        PROTECTED_SOURCE_DOMAIN_JOURNAL,
        source_domain_journal_limits(),
        signer_uid,
        mount.root_identity(),
    )
}

fn replay_source_hold(
    readback: &mut ReadOnlyProtectedJournal,
    project: ProjectId,
) -> Result<SourceDomainPolicyHoldV1, SourceSignerReadbackErrorV1> {
    let journal = readback.journal_mut();
    let hold = journal
        .source_domain_policy_hold_v1()?
        .filter(|hold| hold.is_held())
        .ok_or(SourceSignerReadbackErrorV1::Stale)?;
    let ancestry = replay_project_ancestry_head_v1(journal, project)
        .map_err(|_| SourceSignerReadbackErrorV1::Stale)?
        .ok_or(SourceSignerReadbackErrorV1::Stale)?
        .head();
    if ancestry != hold.ancestry() {
        return Err(SourceSignerReadbackErrorV1::Stale);
    }
    Ok(hold)
}

#[cfg(test)]
mod tests {
    use std::fs;
    use std::os::unix::fs::{MetadataExt, PermissionsExt};

    use aos_sandbox_core::{ObjectDigest, OperationId, SandboxId};

    use super::*;

    #[test]
    fn read_only_source_replay_rejects_missing_head_and_replaced_names() {
        let directory = tempfile::tempdir().expect("Source journal fixture");
        fs::set_permissions(directory.path(), fs::Permissions::from_mode(0o700))
            .expect("private directory");
        let uid = fs::metadata(directory.path()).expect("owner").uid();
        let (mut writer, _) = Journal::open_protected_at_uid(
            directory.path(),
            PROTECTED_SOURCE_DOMAIN_JOURNAL,
            source_domain_journal_limits(),
            uid,
        )
        .expect("protected Source writer");
        let hold = SourceDomainPolicyHoldV1::new(
            OperationId::from_bytes([1; 16]),
            SandboxId::from_bytes([2; 16]),
            ObjectDigest::from_bytes([3; 32]),
            ObjectDigest::from_bytes([4; 32]),
            ObjectDigest::from_bytes([5; 32]),
            6,
        )
        .expect("hold");
        writer
            .acquire_source_domain_policy_hold_v1(hold)
            .expect("write active hold");

        let (mut readback, _) = Journal::open_read_only_protected_at_uid_for_test(
            directory.path(),
            PROTECTED_SOURCE_DOMAIN_JOURNAL,
            source_domain_journal_limits(),
            uid,
        )
        .expect("read-only Source journal");
        assert_eq!(
            readback.physical_names_v1(),
            writer
                .protected_writer_physical_names_v1()
                .expect("writer names")
        );
        assert!(replay_source_hold(&mut readback, ProjectId::from_bytes([9; 16])).is_err());

        for name in [
            PROTECTED_SOURCE_DOMAIN_JOURNAL,
            "source-domains-v1.journal.lock",
        ] {
            let current = directory.path().join(name);
            let retained = directory.path().join(format!("{name}.retained"));
            fs::rename(&current, &retained).expect("move original name");
            fs::write(&current, []).expect("substitute fixed name");
            fs::set_permissions(&current, fs::Permissions::from_mode(0o600))
                .expect("private replacement");
            assert!(readback.check_named_currentness_at_uid_for_test().is_err());
            fs::remove_file(&current).expect("remove replacement");
            fs::rename(&retained, &current).expect("restore original name");
        }
    }
}
