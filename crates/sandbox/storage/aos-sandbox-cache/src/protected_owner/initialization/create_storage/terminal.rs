//! Retains native terminal posts until the actual upper Root6 programme closes.
//!
//! These are the same five writer, physical, clock and selection observations
//! used throughout Held/Released. No supplied phase, clock, result or identity
//! completes this owner. The upper programme keeps the genuine Root6 borrower
//! and can only reject this native continuation before its final positive call.

use super::*;

#[derive(Default)]
pub(super) struct CacheTerminalNativeOriginalsV1 {
    entry: Option<Result<(), CacheHeldClosedV1>>,
    posts: Option<audit::CacheHeldBookendsV1>,
    refused: bool,
    complete: bool,
}

impl CacheTerminalNativeOriginalsV1 {
    pub(super) fn failure(&self) -> Option<&(dyn Error + 'static)> {
        error(&self.entry)
            .or_else(|| self.posts.as_ref().and_then(audit::CacheHeldBookendsV1::failure))
    }

    fn positive(&self) -> bool {
        matches!(self.entry, Some(Ok(())))
            && self.posts.as_ref().is_some_and(|posts| posts.failure().is_none())
            && !self.refused
    }
}

impl OriginalCreateStorageCacheLoanV1<'_> {
    /// Prices the actual native terminal destination and new return planes.
    ///
    /// The genuine U release entry pays this before either terminal Box exists.
    /// The upper supplier separately prices its real Root/currentness/clock.
    ///
    /// # Errors
    /// Rejects checked compiler-layout or resource-vector arithmetic overflow.
    pub fn terminal_receiving_demand_v1() -> Result<ResourceVector, CacheHeldErrorV1> {
        use aos_sandbox_model::ResourceDimension as D;

        let bytes = std::mem::size_of::<CacheTerminalNativeOriginalsV1>()
            .checked_mul(2)
            .and_then(|bytes| bytes.checked_add(std::mem::align_of::<CacheTerminalNativeOriginalsV1>()))
            .and_then(|bytes| bytes.checked_add(
                std::mem::size_of::<Result<(), CacheHeldClosedV1>>().checked_mul(12)?,
            ))
            .and_then(|bytes| bytes.checked_add(
                std::mem::size_of::<CacheHeldIdentityDataV1>().checked_mul(3)?,
            ))
            .and_then(|bytes| bytes.checked_add(
                std::mem::size_of::<Option<&(dyn Error + 'static)>>().checked_mul(3)?,
            ))
            .and_then(|bytes| bytes.checked_add(
                std::mem::size_of::<Result<ResourceVector, CacheHeldErrorV1>>().checked_mul(3)?,
            ))
            .and_then(|bytes| bytes.checked_add(std::mem::size_of::<(
                Option<&CacheReleasedOriginalsV1>,
                Option<&CacheHeldWriterShapeV1>,
                Option<Box<CacheTerminalNativeOriginalsV1>>,
                Option<Box<CacheTerminalNativeOriginalsV1>>,
                Box<CacheTerminalNativeOriginalsV1>,
                [bool; 4],
            )>()))
            .ok_or(CacheHeldErrorV1::Order)?;
        ResourceVector::ZERO
            .with(D::MemoryBytes, u64::try_from(bytes).map_err(|_| CacheHeldErrorV1::Order)?)
            .checked_add(ResourceVector::ZERO)
            .map_err(Into::into)
    }

    /// Installs terminal custody after the same fifteen native audit ordinals.
    ///
    /// This runs before the upper genuine Root6 entry check. Either failure
    /// still owes the native posts and the independent upper currentness IO.
    ///
    /// # Errors
    /// Refuses retained native debt, reentry or incomplete/active native replay.
    pub fn prepare_terminal_native_once_v1(&mut self) -> Result<(), CacheHeldClosedV1> {
        if self.progress.terminal.is_some() || self.progress.finished {
            self.progress.refuse();
            return Err(CacheHeldClosedV1);
        }
        self.progress.terminal = Some(Box::new(CacheTerminalNativeOriginalsV1::default()));
        let entry = if self.progress.first.is_none()
            && self.progress.audit_next == 15
            && self.progress.active_audit.is_none()
        {
            Ok(())
        } else {
            Err(CacheHeldClosedV1)
        };
        self.progress.terminal.as_deref_mut().ok_or(CacheHeldClosedV1)?.entry = Some(entry);
        entry
    }

    /// Retains all original native posts after the real upper Root6 entry.
    ///
    /// The actual Released owner supplies the expected Hold prefix. Its absent
    /// or failed shape preserves the old fallback to the retained Held prefix;
    /// it cannot suppress any independently owed native observation.
    ///
    /// # Errors
    /// Retains native entry/post failure and refuses a repeated post frontier.
    pub fn observe_terminal_native_posts_once_v1(
        &mut self,
        released: Option<&CacheReleasedOriginalsV1>,
    ) -> Result<(), CacheHeldClosedV1> {
        let terminal = self.progress.terminal.as_deref().ok_or(CacheHeldClosedV1)?;
        if terminal.posts.is_some() {
            self.progress.refuse();
            return Err(CacheHeldClosedV1);
        }
        let same_released = match released {
            Some(released) => match released.shape.as_ref() {
                Some(Ok(shape)) => released.complete && !released.refused
                    && released.failure().is_none() && shape.identity_v1() == self.identity,
                _ => false,
            },
            None => false,
        };
        let expected = released.and_then(|released| {
            released.after_hold.as_ref().and_then(|result| result.as_ref().ok())
        });
        let posts = audit::observe_bookends_with_hold_v1(
            &mut self.originals, self.progress, None, expected,
        );
        let terminal = self.progress.terminal.as_deref_mut().ok_or(CacheHeldClosedV1)?;
        terminal.posts = Some(posts);
        terminal.refused |= !same_released;
        self.progress.currentness_site = Some(CacheHeldCurrentnessSiteV1::AfterRoot);
        if terminal.failure().is_some() || terminal.refused {
            Err(CacheHeldClosedV1)
        } else {
            Ok(())
        }
    }

    /// Permanently fences terminal completion after actual upper refusal.
    pub fn reject_terminal_upper_v1(&mut self) {
        if let Some(terminal) = self.progress.terminal.as_deref_mut() {
            terminal.refused = true;
        }
    }

    /// Completes native custody after the actual upper Root6 terminal passes.
    ///
    /// The sole upper caller checks its retained genuine Root6 entry, original
    /// Controller/Source post and paired-clock cutoff before this continuation.
    /// This accepts no supplied success, phase, clock, amount or result.
    ///
    /// # Errors
    /// Refuses native debt, upper refusal, missing posts or repeated completion.
    pub fn finish_terminal_native_once_v1(&mut self) -> Result<(), CacheHeldClosedV1> {
        let terminal = self.progress.terminal.as_deref_mut().ok_or(CacheHeldClosedV1)?;
        if self.progress.first.is_some() || !terminal.positive() || terminal.complete {
            return Err(CacheHeldClosedV1);
        }
        terminal.complete = true;
        self.progress.finished = true;
        Ok(())
    }
}

impl CacheResidentInitializationV1 {
    /// Requires the same initializer's actual completed native Root6 terminal.
    ///
    /// The upper Delete constructor also requires its same retained Root6
    /// result. This predicate neither borrows Initial Create again nor grants
    /// a Delete financial purpose or supplies a replacement original.
    ///
    /// # Errors
    /// Refuses incomplete native custody or any retained native Held debt.
    pub fn require_create_storage_terminal_native_v1(&self) -> Result<(), CacheHeldClosedV1> {
        let held = &self.create_storage_held;
        if held.finished && held.first.is_none()
            && held.terminal.as_deref().is_some_and(|terminal| terminal.complete && terminal.positive())
        {
            Ok(())
        } else {
            Err(CacheHeldClosedV1)
        }
    }
}
