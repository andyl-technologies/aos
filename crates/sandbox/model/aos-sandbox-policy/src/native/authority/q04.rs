//! Borrows one real resident Authority on one native accepted Q04 origin.
//!
//! The native origin remains outside this borrowing work. Its same accepted
//! stream, selected peer, original paired sample and 65-second Instant stay
//! resident; this role independently creates its sole fresh nonce. It accepts
//! no supplied Verified receipt, Authority instance or copied clock as custody.

use aos_sandbox_broker::receiving::{RootQ04OriginBorrowerV1, RootQ04OriginPurposeV1};
use aos_sandbox_model::{RawPairedClockSample, ResourceDimension as D, ResourceVector};

use super::RootAuthorityOriginalV1;
use super::error::RootAuthorityErrorV1;
use crate::native::PolicyNativeJournalErrorV1;
use crate::native::journal::PolicyJournalStorageV1;

/// Retains one same-origin Q04 association over the actual resident Authority.
///
/// The origin is externally owned, so storing the role borrower creates no
/// self-reference or second native writer. Actual per-flight acceptance and
/// current-floor loans cannot outlive this borrow of the real Authority.
pub struct RootAuthorityQ04FlightOriginalV1<'authority, 'origin, 'startup> {
    pub(super) authority: &'authority mut RootAuthorityOriginalV1,
    pub(super) origin: RootQ04OriginBorrowerV1<'origin, 'startup>,
    entry: Option<Result<(), RootAuthorityErrorV1>>,
    pub(super) forecast: super::forecast::RootAuthorityQ04ForecastOriginalV1,
    pub(super) history: Option<super::binding_history::RootAuthorityQ04HistoryV1>,
    pub(super) history_admission: Option<Result<(), RootAuthorityErrorV1>>,
    admission: Option<Result<(), PolicyNativeJournalErrorV1>>,
    pub(super) nonce: Option<std::io::Result<[u8; 16]>>,
    pub(super) identities: Option<[u32; 4]>,
    pub(super) accepted: Option<aos_sandbox_ledger_replay::source_signer_data::controller_genesis_readback::ControllerGenesisReadbackDataV1>,
    entered: bool,
    closed: bool,
}

impl<'authority, 'origin, 'startup>
    RootAuthorityQ04FlightOriginalV1<'authority, 'origin, 'startup>
{
    /// Borrows genuine owners into inert fields without native IO or allocation.
    ///
    /// The actual upper Root receiver pays the complete constructor/control
    /// footprint before constructing its work; this method accepts no payer
    /// DATA, success marker or replacement native parts.
    #[must_use]
    pub fn new(
        authority: &'authority mut RootAuthorityOriginalV1,
        origin: RootQ04OriginBorrowerV1<'origin, 'startup>,
    ) -> Self {
        Self {
            authority,
            origin,
            entry: None,
            forecast: super::forecast::RootAuthorityQ04ForecastOriginalV1::new(),
            history: None,
            history_admission: None,
            admission: None,
            nonce: None,
            identities: None,
            accepted: None,
            entered: false,
            closed: false,
        }
    }

    /// Bounds the actual inert role constructor, resident and return carriers.
    ///
    /// The native Origin's own supplier remains separately required. This
    /// method neither pays nor constructs a native or financial original.
    #[must_use]
    pub fn fixed_carrier_demand_v1() -> Option<ResourceVector> {
        let bytes = std::mem::size_of::<Self>().checked_mul(3)?;
        Some(ResourceVector::ZERO.with(D::MemoryBytes, u64::try_from(bytes).ok()?))
    }

    /// Claims this actual accepted origin and creates its independent Root nonce.
    ///
    /// The same-permanent comparison and immutable profile/peer joins precede
    /// entropy. The actual held Authority pays the entropy carrier before its
    /// construction. Entropy runs under the genuine native Origin loan; that
    /// loan ends before any subsequent role debit or observation.
    ///
    /// # Errors
    /// Returns a marker retaining the actual origin, financial or entropy
    /// failure in this same role. Reentry permanently refuses this borrower.
    pub fn begin_once(&mut self) -> Result<(), ()> {
        if self.entered || self.closed {
            self.closed = true;
            return Err(());
        }
        self.entered = true;
        self.entry = Some((|| {
            let mut origin = self.origin.try_borrow_mut()?;
            origin.claim_authority_flight_once_v1()?;
            match (&self.authority.journal.storage, self.origin.purpose_v1()) {
                (
                    PolicyJournalStorageV1::Selected { financial, .. },
                    RootQ04OriginPurposeV1::Selected,
                ) => {
                    origin.require_selected_financial_original_v1(financial)?;
                }
                (PolicyJournalStorageV1::Ordinary { .. }, RootQ04OriginPurposeV1::Ordinary) => {
                    origin.require_ordinary_original_v1()?;
                }
                _ => return Err(RootAuthorityErrorV1::Stale),
            }
            let identities = origin.expected_identities_data_v1()?;
            let peer = origin.qualified_peer_credentials_data_v1()?;
            if peer.uid() != identities[0]
                || peer.gid() != identities[1]
                || identities[0] == 0
                || identities[2] != identities[0]
                || identities[2] == 0
                || identities[3] == 0
            {
                return Err(RootAuthorityErrorV1::Stale);
            }
            self.identities = Some(identities);
            Ok(())
        })());
        if !matches!(self.entry, Some(Ok(()))) {
            self.closed = true;
            return Err(());
        }

        let bytes = std::mem::size_of::<[u8; 16]>()
            .checked_mul(3)
            .and_then(|bytes| u64::try_from(bytes).ok())
            .ok_or(())?;
        self.admission = Some(
            self.authority
                .journal
                .admit_role_observation_v1(ResourceVector::ZERO.with(D::MemoryBytes, bytes)),
        );
        if !matches!(self.admission, Some(Ok(()))) {
            self.closed = true;
            return Err(());
        }
        self.entry = Some((|| {
            if self.origin.purpose_v1() == RootQ04OriginPurposeV1::Selected {
                self.authority.recheck()?;
            }
            {
                let mut origin = self.origin.try_borrow_mut()?;
                let native = origin.borrow_native_stream_v1()?;
                self.nonce = Some(aos_sandbox_broker::root_nonce::fresh_root_nonce());
                drop(native);
            }
            // The old ordinary factory creates its nonce after pins/history
            // and names, then performs its full final Authority recheck.
            if self.origin.purpose_v1() == RootQ04OriginPurposeV1::Ordinary
                && matches!(self.nonce, Some(Ok(_)))
            {
                self.authority.recheck()?;
            }
            Ok(())
        })());
        if !matches!(self.entry, Some(Ok(()))) || !matches!(self.nonce, Some(Ok(_))) {
            self.closed = true;
            return Err(());
        }
        Ok(())
    }

    pub(super) fn require_ready(&self) -> Result<(), RootAuthorityErrorV1> {
        if self.closed
            || !self.entered
            || !matches!(self.entry, Some(Ok(())))
            || !matches!(self.admission, Some(Ok(())))
            || !matches!(self.nonce, Some(Ok(_)))
        {
            return Err(RootAuthorityErrorV1::Stale);
        }
        Ok(())
    }

    /// Compares the passed closed borrower with this flight's same actual Origin.
    ///
    /// # Errors
    /// Refuses an unentered/failed role or a different native original/purpose.
    pub fn require_same_origin_v1(
        &self,
        original: &RootQ04OriginBorrowerV1<'origin, 'startup>,
    ) -> Result<(), RootAuthorityErrorV1> {
        self.require_ready()?;
        if self.origin.same_origin_v1(original) {
            Ok(())
        } else {
            Err(RootAuthorityErrorV1::Stale)
        }
    }

    /// Copies this entered flight's actual privileged Q04 role identities.
    ///
    /// # Errors
    /// Refuses missing original admission or a failed native role association.
    pub fn identities_data_v1(&self) -> Result<[u32; 4], RootAuthorityErrorV1> {
        self.require_ready()?;
        self.identities.ok_or(RootAuthorityErrorV1::Stale)
    }

    /// Copies the same accepted request without observing a new endpoint.
    ///
    /// # Errors
    /// Preserves an overlapping original borrow or incomplete/refused admission.
    pub fn request_data_v1(&self) -> Result<[u8; 32], RootAuthorityErrorV1> {
        self.require_ready()?;
        Ok(*self.origin.try_borrow_mut()?.accepted_query_data_v1()?)
    }

    /// Rechecks the same resident Authority at the original owner frontier.
    ///
    /// The enclosing selected driver performs its startup/peer/queue prefix and
    /// final original clock around this call. Repeating those transport posts
    /// here would change their order and create a second currentness path.
    ///
    /// # Errors
    /// Preserves an unentered flight or actual Authority currentness refusal.
    pub fn recheck(&self) -> Result<(), RootAuthorityErrorV1> {
        self.require_ready()?;
        self.authority.recheck()
    }

    /// Observes the actual Authority rows and native names for a Q04 forecast.
    ///
    /// # Errors
    /// Preserves the genuine owner's currentness or complete native-readback failure.
    pub fn q04_before_rows(
        &self,
    ) -> Result<
        (
            u64,
            aos_sandbox_protocol::domain_ledger::protected_names::ProtectedJournalNamesV1,
            aos_sandbox_model::ObjectDigest,
        ),
        RootAuthorityErrorV1,
    > {
        self.recheck()?;
        Ok(self.authority.journal.q04_before_rows_v1()?)
    }

    /// Copies the same actual original clock association without observing again.
    ///
    /// # Errors
    /// Rejects an unentered/refused role or incomplete original native clock.
    pub fn original_clock_data_v1(
        &self,
    ) -> Result<(RawPairedClockSample, std::time::Instant), RootAuthorityErrorV1> {
        self.require_ready()?;
        Ok(self.origin.try_borrow_mut()?.retained_original_clock_data_v1()?)
    }

    /// Resolves an already held same-flight Authority marker without another IO.
    ///
    /// Only currentness and Q04 readback markers borrow their corresponding
    /// resident source. Other error categories keep the supplied owning cause.
    /// The caller's first-owner selector remains responsible for chronology.
    #[must_use]
    pub fn resolve_held_failure_v1<'error>(
        &'error self,
        cause: &'error RootAuthorityErrorV1,
    ) -> &'error (dyn std::error::Error + 'static) {
        self.authority.resolve_held_failure_v1(cause)
    }

    /// Borrows the actual first entered cause without allocation or another IO.
    #[must_use]
    pub fn failure(&self) -> Option<&(dyn std::error::Error + 'static)> {
        self.entry
            .as_ref()
            .and_then(|result| result.as_ref().err())
            .map(|error| error as _)
            .or_else(|| {
                self.admission
                    .as_ref()
                    .and_then(|result| result.as_ref().err())
                    .map(|error| error as _)
            })
            .or_else(|| {
                self.nonce
                    .as_ref()
                    .and_then(|result| result.as_ref().err())
                    .map(|error| error as _)
            })
            .or_else(|| {
                self.history_admission
                    .as_ref()
                    .and_then(|result| result.as_ref().err())
                    .map(|cause| cause as _)
            })
            .or_else(|| {
                self.history
                    .as_ref()
                    .and_then(super::binding_history::RootAuthorityQ04HistoryV1::failure_v1)
            })
            .or_else(|| self.forecast.failure_v1())
            .or_else(|| self.authority.retained_failure())
            .map(|cause| match cause.downcast_ref::<RootAuthorityErrorV1>() {
                Some(cause) => self.authority.resolve_held_failure_v1(cause),
                None => cause,
            })
    }
}

impl<'authority, 'origin, 'startup>
    RootAuthorityQ04FlightOriginalV1<'authority, 'origin, 'startup>
{
    // Native source-observation work borrows the same accepted transport before
    // Controller Complete. This finite input-current loan grants no floor or
    // publication authority and retains no borrow of the Authority journal.
    pub(in crate::native) fn original_transport_ready_v1(
        &self,
    ) -> Result<RootQ04OriginBorrowerV1<'origin, 'startup>, RootAuthorityErrorV1> {
        self.require_ready()?;
        Ok(self.origin)
    }
}
