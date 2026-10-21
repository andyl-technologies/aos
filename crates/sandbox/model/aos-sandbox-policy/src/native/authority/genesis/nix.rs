//! Retains the actual held Root archive and all independent Nix readback posts.
//!
//! The same fixed ordinary Authority remains held while Controller and Source
//! signatures are compared. This read-only path issues neither a mutation loan
//! nor a replacement native authority from its archive DATA.

use super::super::RootAuthorityErrorV1;
use super::{FirstSuccessorWireRecipeV3, RootSourceGenesisAuthorityV1};
use crate::nix_current_data::{
    CurrentNixPreflightContextV1, CurrentNixPreflightDataErrorV1,
    VerifiedCurrentNixControllerReceiptV1, VerifiedCurrentNixSourceObservationV1,
};
use aos_sandbox_model::ProjectId;

// Only the same already-held Root writer constructs this archive capture.
pub(self) struct CurrentNixRootArchiveDataV1 {
    pub(self) floor:
        aos_sandbox_ledger_replay::replay::phase_records::RootFirstSourceSuccessorFloorV2,
    pub(self) original:
        aos_sandbox_ledger_replay::replay::phase_records::RootFirstSourceSuccessorIntentV2,
    pub(self) nonce: [u8; 16],
    pub(self) sequence: u64,
    pub(self) recipe: u8,
}

/// Retains a purpose-closed current-Nix Root capture without issuing permission.
///
/// Its external Root writer stays held. Every returned comparison precedes its
/// independent native post; decoded packets cannot replace that original owner.
pub struct CurrentNixRootArchiveAttemptV1 {
    pub(self) entered: bool,
    pub(self) refusal: Option<RootAuthorityErrorV1>,
    pub(self) before: Option<Result<(), RootAuthorityErrorV1>>,
    pub(self) archive: Option<Result<CurrentNixRootArchiveDataV1, RootAuthorityErrorV1>>,
    controller_pin: Option<RootAuthorityErrorV1>,
    source_pin: Option<RootAuthorityErrorV1>,
    pub(self) controller:
        Option<Result<VerifiedCurrentNixControllerReceiptV1, CurrentNixPreflightDataErrorV1>>,
    pub(self) source:
        Option<Result<VerifiedCurrentNixSourceObservationV1, CurrentNixPreflightDataErrorV1>>,
    pub(self) comparison: Option<Result<(), RootAuthorityErrorV1>>,
    pub(self) posts: [Option<Result<(), RootAuthorityErrorV1>>; 3],
    pub(self) used_posts: usize,
}

impl CurrentNixRootArchiveAttemptV1 {
    /// Prearms fixed capture and comparison slots without opening any writer.
    pub const fn empty() -> Self {
        Self {
            entered: false,
            refusal: None,
            before: None,
            archive: None,
            controller_pin: None,
            source_pin: None,
            controller: None,
            source: None,
            comparison: None,
            posts: [const { None }; 3],
            used_posts: 0,
        }
    }

    /// Borrows the earliest resident failure without another observation.
    pub fn failure(&self) -> Option<&(dyn std::error::Error + 'static)> {
        if let Some(Err(error)) = &self.before {
            return Some(error);
        }
        if let Some(Err(error)) = &self.archive {
            return Some(error);
        }
        if let Some(Err(error)) = &self.posts[0] {
            return Some(error);
        }
        if let Some(error) = &self.controller_pin {
            return Some(error);
        }
        if let Some(Err(error)) = &self.controller {
            return Some(error);
        }
        if let Some(Err(error)) = &self.posts[1] {
            return Some(error);
        }
        if let Some(error) = &self.source_pin {
            return Some(error);
        }
        if let Some(Err(error)) = &self.source {
            return Some(error);
        }
        if let Some(Err(error)) = &self.comparison {
            return Some(error);
        }
        if let Some(Err(error)) = &self.posts[2] {
            return Some(error);
        }
        self.refusal.as_ref().map(|error| error as _)
    }
}

impl RootSourceGenesisAuthorityV1 {
    // The fresh nonce was obtained by the same native opening, not supplied by
    // the framing peer. This comparison DATA never lends the Root writer.
    /// Returns the nonce from this same opening after actual Root revalidation.
    ///
    /// # Errors
    /// Retains changed writer, complete history or role-credential refusal.
    pub fn current_nix_challenge_data_v1(&self) -> Result<[u8; 16], RootAuthorityErrorV1> {
        self.recheck()?;
        Ok(self.nonce)
    }

    /// Captures the actual held archive and its independently owed Root post.
    ///
    /// # Errors
    /// Returns a marker retaining repeated entry, changed native custody or an
    /// absent/conflicting complete archive in the original attempt.
    pub fn capture_current_nix_archive_into_v1(
        &self,
        attempt: &mut CurrentNixRootArchiveAttemptV1,
        project: ProjectId,
    ) -> Result<(), ()> {
        if attempt.entered {
            attempt.refusal = Some(RootAuthorityErrorV1::Conflict);
            return Err(());
        }
        attempt.entered = true;
        attempt.before = Some(self.recheck());
        if matches!(attempt.before, Some(Ok(()))) {
            let returned = self
                .successor_rows_for_project_v3(project)
                .and_then(|rows| {
                    if rows.intent.is_some() {
                        return Err(RootAuthorityErrorV1::Conflict);
                    }
                    let archive = rows.archive.ok_or(RootAuthorityErrorV1::Conflict)?;
                    if archive.original.project() != project {
                        return Err(RootAuthorityErrorV1::Conflict);
                    }
                    let recipe = match (
                        self.successor_recipe,
                        archive
                            .original
                            .approval_packet()
                            .has_resource_authorization(),
                    ) {
                        (FirstSuccessorWireRecipeV3::StrictV2, false) => 1,
                        (FirstSuccessorWireRecipeV3::MixedV3, false) => 2,
                        (FirstSuccessorWireRecipeV3::StrictV2, true) => 3,
                        (FirstSuccessorWireRecipeV3::MixedV3, true) => 4,
                    };
                    Ok(CurrentNixRootArchiveDataV1 {
                        floor: archive.floor,
                        original: archive.original,
                        nonce: self.nonce,
                        sequence: self.authority.journal.next_sequence(),
                        recipe,
                    })
                });
            attempt.archive = Some(returned);
        }
        attempt.posts[0] = Some(self.recheck());
        attempt.used_posts = 1;
        if attempt.failure().is_some() {
            Err(())
        } else {
            Ok(())
        }
    }

    /// Compares the Controller signature with the same captured Root context.
    ///
    /// # Errors
    /// Retains an out-of-order call, failed role credential, foreign packet or
    /// independently failed native Root post in the actual attempt.
    pub fn join_current_nix_controller_into_v1(
        &self,
        attempt: &mut CurrentNixRootArchiveAttemptV1,
        context: &CurrentNixPreflightContextV1,
        receipt: &[u8],
    ) -> Result<(), ()> {
        if attempt.used_posts != 1 || attempt.controller.is_some() || attempt.failure().is_some() {
            attempt.refusal = Some(RootAuthorityErrorV1::Conflict);
            return Err(());
        }
        match self.authority.pins.controller() {
            Ok(pin) => {
                attempt.controller = Some(VerifiedCurrentNixControllerReceiptV1::verify_data(
                    receipt,
                    context,
                    pin,
                    self.controller_uid,
                    self.source_uid,
                ))
            }
            Err(cause) => attempt.controller_pin = Some(cause),
        }
        attempt.posts[1] = Some(self.recheck());
        attempt.used_posts = 2;
        if attempt.failure().is_some() {
            Err(())
        } else {
            Ok(())
        }
    }

    /// Joins the exact Source observation and archive before its Root post.
    ///
    /// # Errors
    /// Retains an out-of-order call, failed Source credential/signature, changed
    /// complete archive association or independently failed native post.
    pub fn join_current_nix_source_into_v1(
        &self,
        attempt: &mut CurrentNixRootArchiveAttemptV1,
        context: &CurrentNixPreflightContextV1,
        reply: &[u8],
    ) -> Result<(), ()> {
        if attempt.used_posts != 2 || attempt.source.is_some() || attempt.failure().is_some() {
            attempt.refusal = Some(RootAuthorityErrorV1::Conflict);
            return Err(());
        }
        if let Some(Ok(archive)) = &attempt.archive {
            match self.authority.pins.source() {
                Ok(pin) => {
                    attempt.source = Some(VerifiedCurrentNixSourceObservationV1::verify_data(
                        reply,
                        context,
                        &archive.original,
                        pin,
                    ))
                }
                Err(cause) => attempt.source_pin = Some(cause),
            }
            if let Some(Ok(source)) = &attempt.source {
                attempt.comparison = Some(
                    source
                        .require_original_root_archive_data_v1(
                            context,
                            archive.nonce,
                            archive.sequence,
                            archive.recipe,
                            &archive.floor,
                            &archive.original,
                        )
                        .map_err(|_| RootAuthorityErrorV1::Stale),
                );
            }
        }
        attempt.posts[2] = Some(self.recheck());
        attempt.used_posts = 3;
        if attempt.failure().is_some() {
            Err(())
        } else {
            Ok(())
        }
    }
}
