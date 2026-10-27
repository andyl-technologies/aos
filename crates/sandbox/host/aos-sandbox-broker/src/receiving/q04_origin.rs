//! Borrows the real selected or ordinary Q04 origin through a closed purpose.
//!
//! A role matches its actual journal purpose explicitly. Financial absence or
//! selected refusal never chooses the ordinary branch. Both branches borrow
//! native originals; neither accepts peer, clock or phase DATA as custody.

mod ordinary;

use std::cell::{BorrowError, BorrowMutError, Ref, RefCell, RefMut};
use std::time::Instant;

use aos_sandbox_model::RawPairedClockSample;
use aos_linux_descriptors::unix_stream::RetainedUnixStream;
use aos_linux_descriptors::unix_stream::UnixStreamPeerCredentials;
use aos_sandbox_linux::unix_stream::UnixStreamSubjectChunk;

use super::{
    RootJournalFinancialOriginalV1, RootObservationErrorV1, RootQ04InputCurrentLoanV1,
    RootQ04NativeStreamLoanV1, RootQ04TransportOriginalV1,
};

pub use ordinary::{RootQ04OrdinaryTransportErrorV1, RootQ04OrdinaryTransportOriginalV1};

/// Identifies the real native origin's distinct construction purpose as DATA.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum RootQ04OriginPurposeV1 {
    /// Requires the genuine selected Initial/Permanent and same financial link.
    Selected,
    /// Requires the explicit ordinary original and actual legacy startup.
    Ordinary,
}

/// Preserves the actual closed-origin failure without granting a role.
#[derive(Debug, thiserror::Error)]
pub enum RootQ04OriginErrorV1 {
    /// The same selected native original retained its observation refusal.
    #[error(transparent)]
    Selected(#[from] RootObservationErrorV1),
    /// The explicit ordinary original preserves its existing typed cause.
    #[error(transparent)]
    Ordinary(#[from] RootQ04OrdinaryTransportErrorV1),
    /// The real role and native-origin purposes differ.
    #[error("Q04 role and native origin purposes differ")]
    Purpose,
    /// The actual ordinary original still has an outstanding mutable borrow.
    #[error(transparent)]
    Borrow(#[from] BorrowError),
}

#[derive(Clone, Copy)]
enum OriginKind<'origin, 'startup> {
    Selected(&'origin RefCell<RootQ04TransportOriginalV1<'startup>>),
    Ordinary(&'origin RefCell<RootQ04OrdinaryTransportOriginalV1<'startup>>),
}

/// Borrows one actual original without creating a second transport owner.
#[derive(Clone, Copy)]
pub struct RootQ04OriginBorrowerV1<'origin, 'startup> {
    original: OriginKind<'origin, 'startup>,
}

impl<'origin, 'startup> RootQ04OriginBorrowerV1<'origin, 'startup> {
    /// Bounds this closed borrower's concrete construction and return controls.
    ///
    /// The selected Origin's actual existing fixed supplier includes these
    /// lanes before construction. Ordinary retains its explicit existing
    /// allocation policy; this DATA does not invent an ordinary financial link.
    #[must_use]
    pub fn fixed_carrier_demand_v1() -> Option<aos_sandbox_model::ResourceVector> {
        use aos_sandbox_model::{ResourceDimension as D, ResourceVector};
        let bytes = std::mem::size_of::<Self>()
            .checked_mul(3)?
            .checked_add(std::mem::size_of::<OriginKind<'_, '_>>().checked_mul(2)?)?
            .checked_add(std::mem::size_of::<RootQ04OriginPurposeV1>().checked_mul(3)?)?
            .checked_add(std::mem::size_of::<(&Self, &Self)>().checked_mul(3)?)?
            .checked_add(std::mem::size_of::<bool>().checked_mul(3)?)?
            .checked_add(std::mem::size_of::<LoanKind<'_, '_>>().checked_mul(3)?)?
            .checked_add(
                std::mem::size_of::<
                    Result<RefMut<'_, RootQ04TransportOriginalV1<'_>>, BorrowMutError>,
                >()
                .checked_mul(3)?,
            )?
            .checked_add(
                std::mem::size_of::<
                    Result<RefMut<'_, RootQ04OrdinaryTransportOriginalV1<'_>>, BorrowMutError>,
                >()
                .checked_mul(3)?,
            )?
            .checked_add(std::mem::size_of::<RootQ04OriginLoanV1<'_, '_>>().checked_mul(3)?)?
            .checked_add(
                std::mem::size_of::<Result<RootQ04OriginLoanV1<'_, '_>, BorrowMutError>>()
                    .checked_mul(3)?,
            )?
            .checked_add(std::mem::size_of::<&RootQ04OriginLoanV1<'_, '_>>().checked_mul(3)?)?
            .checked_add(std::mem::size_of::<&mut RootQ04OriginLoanV1<'_, '_>>().checked_mul(3)?)?
            .checked_add(std::mem::size_of::<&RootJournalFinancialOriginalV1>().checked_mul(3)?)?
            .checked_add(std::mem::size_of::<Result<(), RootQ04OriginErrorV1>>().checked_mul(6)?)?
            .checked_add(
                std::mem::size_of::<Result<(RawPairedClockSample, Instant), RootQ04OriginErrorV1>>(
                )
                .checked_mul(3)?,
            )?
            .checked_add(
                std::mem::size_of::<Result<&[u8; 32], RootQ04OriginErrorV1>>().checked_mul(3)?,
            )?
            .checked_add(
                std::mem::size_of::<Result<[u32; 4], RootQ04OriginErrorV1>>().checked_mul(3)?,
            )?
            .checked_add(
                std::mem::size_of::<Result<UnixStreamPeerCredentials, RootQ04OriginErrorV1>>()
                    .checked_mul(3)?,
            )?
            .checked_add(
                std::mem::size_of::<Result<RawPairedClockSample, RootQ04OriginErrorV1>>()
                    .checked_mul(3)?,
            )?
            .checked_add(
                std::mem::size_of::<RootQ04OriginNativeStreamLoanV1<'_>>().checked_mul(3)?,
            )?
            .checked_add(std::mem::size_of::<StreamKind<'_>>().checked_mul(2)?)?
            .checked_add(
                std::mem::size_of::<
                    Result<RootQ04OriginNativeStreamLoanV1<'_>, RootQ04OriginErrorV1>,
                >()
                .checked_mul(3)?,
            )?
            .checked_add(
                std::mem::size_of::<RootQ04OriginInputCurrentLoanV1<'_, '_>>().checked_mul(3)?,
            )?
            .checked_add(std::mem::size_of::<CurrentKind<'_, '_>>().checked_mul(2)?)?
            .checked_add(
                std::mem::size_of::<
                    Result<RootQ04OriginInputCurrentLoanV1<'_, '_>, RootQ04OriginErrorV1>,
                >()
                .checked_mul(3)?,
            )?
            .checked_add(
                std::mem::size_of::<
                    Result<Ref<'_, RootQ04OrdinaryTransportOriginalV1<'_>>, BorrowError>,
                >()
                .checked_mul(3)?,
            )?
            .checked_add(
                std::mem::size_of::<
                    Result<
                        Ref<'_, Result<(), std::io::Error>>,
                        Ref<'_, RootQ04OrdinaryTransportOriginalV1<'_>>,
                    >,
                >()
                .checked_mul(3)?,
            )?
            .checked_add(
                std::mem::size_of::<Option<Ref<'_, Result<(), std::io::Error>>>>()
                    .checked_mul(3)?,
            )?
            .checked_add(
                std::mem::size_of::<
                    Result<Option<Ref<'_, Result<(), std::io::Error>>>, RootQ04OriginErrorV1>,
                >()
                .checked_mul(3)?,
            )?
            .checked_add(
                std::mem::size_of::<&RootQ04OrdinaryTransportOriginalV1<'_>>().checked_mul(3)?,
            )?
            .checked_add(
                std::mem::size_of::<Option<&Result<(), std::io::Error>>>().checked_mul(3)?,
            )?
            // Both passive association forwarding layers are additional to
            // the actual existing currentness/healthy-entry result planes.
            .checked_add(std::mem::size_of::<(
                &RootQ04TransportOriginalV1<'_>, &RootJournalFinancialOriginalV1,
            )>().checked_mul(3)?)?
            .checked_add(std::mem::size_of::<(
                &RootQ04OriginLoanV1<'_, '_>, &RootJournalFinancialOriginalV1,
            )>().checked_mul(3)?)?
            .checked_add(std::mem::size_of::<Option<&RootJournalFinancialOriginalV1>>().checked_mul(3)?)?
            .checked_add(std::mem::size_of::<bool>().checked_mul(6)?)?
            // The retained DATA helper adds one nested forwarding layer to
            // active clock getters and its distinct inert Input call surface.
            .checked_add(std::mem::size_of::<Result<
                (RawPairedClockSample, Instant), RootObservationErrorV1,
            >>().checked_mul(6)?)?
            .checked_add(std::mem::size_of::<Result<
                (RawPairedClockSample, Instant), RootQ04OrdinaryTransportErrorV1,
            >>().checked_mul(6)?)?
            .checked_add(std::mem::size_of::<Result<
                (RawPairedClockSample, Instant), RootQ04OriginErrorV1,
            >>().checked_mul(3)?)?
            .checked_add(std::mem::size_of::<&RootQ04TransportOriginalV1<'_>>().checked_mul(3)?)?
            .checked_add(std::mem::size_of::<&RootQ04OrdinaryTransportOriginalV1<'_>>().checked_mul(3)?)?
            .checked_add(std::mem::size_of::<&RootQ04OriginLoanV1<'_, '_>>().checked_mul(3)?)?;
        Some(ResourceVector::ZERO.with(D::MemoryBytes, u64::try_from(bytes).ok()?))
    }

    /// Borrows the actual selected origin without completing any admission.
    #[must_use]
    pub fn selected(original: &'origin RefCell<RootQ04TransportOriginalV1<'startup>>) -> Self {
        Self {
            original: OriginKind::Selected(original),
        }
    }

    /// Borrows the actual ordinary origin without supplying a selected lender.
    #[must_use]
    pub fn ordinary(
        original: &'origin RefCell<RootQ04OrdinaryTransportOriginalV1<'startup>>,
    ) -> Self {
        Self {
            original: OriginKind::Ordinary(original),
        }
    }

    /// Returns the real original's construction purpose as comparison DATA.
    #[must_use]
    pub fn purpose_v1(&self) -> RootQ04OriginPurposeV1 {
        match self.original {
            OriginKind::Selected(_) => RootQ04OriginPurposeV1::Selected,
            OriginKind::Ordinary(_) => RootQ04OriginPurposeV1::Ordinary,
        }
    }

    /// Compares the variant and actual original allocation without observing.
    #[must_use]
    pub fn same_origin_v1(&self, other: &Self) -> bool {
        match (self.original, other.original) {
            (OriginKind::Selected(left), OriginKind::Selected(right)) => std::ptr::eq(left, right),
            (OriginKind::Ordinary(left), OriginKind::Ordinary(right)) => std::ptr::eq(left, right),
            _ => false,
        }
    }

    /// Borrows the same native original for one bounded lexical operation.
    ///
    /// # Errors
    /// Preserves an overlapping real mutable borrow; it never retries or
    /// changes the selected purpose after a failed borrow.
    pub fn try_borrow_mut(&self) -> Result<RootQ04OriginLoanV1<'origin, 'startup>, BorrowMutError> {
        Ok(RootQ04OriginLoanV1 {
            original: match self.original {
                OriginKind::Selected(original) => LoanKind::Selected(original.try_borrow_mut()?),
                OriginKind::Ordinary(original) => LoanKind::Ordinary(original.try_borrow_mut()?),
            },
        })
    }
    /// Borrows the real ordinary shutdown result without moving its cause.
    ///
    /// # Errors
    /// Refuses selected purpose or an overlapping actual mutable borrow.
    pub fn ordinary_shutdown_result_v1(
        &self,
    ) -> Result<Option<Ref<'origin, Result<(), std::io::Error>>>, RootQ04OriginErrorV1> {
        match self.original {
            OriginKind::Ordinary(original) => {
                let original = original.try_borrow()?;
                Ok(Ref::filter_map(original, |original| original.shutdown_result()).ok())
            }
            OriginKind::Selected(_) => Err(RootQ04OriginErrorV1::Purpose),
        }
    }
}

enum LoanKind<'origin, 'startup> {
    Selected(RefMut<'origin, RootQ04TransportOriginalV1<'startup>>),
    Ordinary(RefMut<'origin, RootQ04OrdinaryTransportOriginalV1<'startup>>),
}

/// Keeps the real mutable-origin borrow through one closed native entry.
pub struct RootQ04OriginLoanV1<'origin, 'startup> {
    original: LoanKind<'origin, 'startup>,
}

macro_rules! original_data {
    ($name:ident, $output:ty, $summary:literal) => {
        #[doc = $summary]
        ///
        /// # Errors
        /// Preserves incomplete or refused actual native-origin custody.
        pub fn $name(&self) -> Result<$output, RootQ04OriginErrorV1> {
            match &self.original {
                LoanKind::Selected(original) => original.$name().map_err(Into::into),
                LoanKind::Ordinary(original) => original.$name().map_err(Into::into),
            }
        }
    };
}

impl<'origin, 'startup> RootQ04OriginLoanV1<'origin, 'startup> {
    original_data!(
        require_ready_v1,
        (),
        "Requires the actual native origin's completed prefix."
    );
    original_data!(
        original_clock_data_v1,
        (RawPairedClockSample, Instant),
        "Copies only the same original clock association."
    );
    original_data!(
        retained_original_clock_data_v1,
        (RawPairedClockSample, Instant),
        "Copies only this actual Origin's retained first clock DATA without currentness."
    );
    original_data!(
        accepted_query_data_v1,
        &[u8; 32],
        "Borrows the actual accepted request as comparison DATA."
    );
    original_data!(
        expected_identities_data_v1,
        [u32; 4],
        "Copies the actual Q04 role identities as comparison DATA."
    );
    original_data!(
        qualified_peer_credentials_data_v1,
        UnixStreamPeerCredentials,
        "Copies the actual qualified native peer credentials."
    );

    /// Rejoins only a selected origin with its genuine financial original.
    ///
    /// # Errors
    /// Refuses ordinary purpose or the selected origin's actual financial join.
    pub fn require_selected_financial_original_v1(
        &self,
        financial: &RootJournalFinancialOriginalV1,
    ) -> Result<(), RootQ04OriginErrorV1> {
        match &self.original {
            LoanKind::Selected(original) => original
                .require_same_financial_original_v1(financial)
                .map_err(Into::into),
            LoanKind::Ordinary(_) => Err(RootQ04OriginErrorV1::Purpose),
        }
    }

    /// Compares only the real selected Origin's intrinsic financial allocation.
    ///
    /// No readiness, deadline, native phase or observation is entered. Ordinary
    /// purpose is always false; a financial absence never selects that branch.
    #[must_use]
    pub fn same_selected_financial_original_data_v1(
        &self,
        financial: &RootJournalFinancialOriginalV1,
    ) -> bool {
        match &self.original {
            LoanKind::Selected(original) => original.same_financial_original_data_v1(financial),
            LoanKind::Ordinary(_) => false,
        }
    }

    /// Rejoins only an explicit ordinary origin with its actual legacy startup.
    ///
    /// # Errors
    /// Refuses selected purpose, absent startup or an incomplete ordinary cut.
    pub fn require_ordinary_original_v1(&self) -> Result<(), RootQ04OriginErrorV1> {
        match &self.original {
            LoanKind::Ordinary(original) => {
                original.require_ordinary_original_v1().map_err(Into::into)
            }
            LoanKind::Selected(_) => Err(RootQ04OriginErrorV1::Purpose),
        }
    }

    /// Claims the real original's sole Authority programme association.
    ///
    /// # Errors
    /// Preserves native refusal or repeated entry without generating a nonce.
    pub fn claim_authority_flight_once_v1(&mut self) -> Result<(), RootQ04OriginErrorV1> {
        match &mut self.original {
            LoanKind::Selected(original) => original
                .claim_authority_flight_once_v1()
                .map_err(Into::into),
            LoanKind::Ordinary(original) => original
                .claim_authority_flight_once_v1()
                .map_err(Into::into),
        }
    }

    /// Borrows the actual endpoint under its original native custody.
    ///
    /// # Errors
    /// Preserves refused native entry; ordinary cannot acquire a selected N.
    pub fn borrow_native_stream_v1(
        &mut self,
    ) -> Result<RootQ04OriginNativeStreamLoanV1<'_>, RootQ04OriginErrorV1> {
        Ok(RootQ04OriginNativeStreamLoanV1 {
            stream: match &mut self.original {
                LoanKind::Selected(original) => {
                    StreamKind::Selected(original.borrow_native_stream_v1()?)
                }
                LoanKind::Ordinary(original) => StreamKind::Ordinary(original.stream_mut_v1()?),
            },
        })
    }

    /// Begins the actual startup, peer and queue prefix before a target check.
    ///
    /// # Errors
    /// Preserves original prefix refusal and the selected branch's owed posts.
    pub fn begin_input_current_once_v1(
        &mut self,
    ) -> Result<RootQ04OriginInputCurrentLoanV1<'_, 'startup>, RootQ04OriginErrorV1> {
        Ok(RootQ04OriginInputCurrentLoanV1 {
            original: match &mut self.original {
                LoanKind::Selected(original) => {
                    CurrentKind::Selected(original.begin_input_current_once_v1()?)
                }
                LoanKind::Ordinary(original) => {
                    original.observe_prefix_once_v1()?;
                    CurrentKind::Ordinary(original)
                }
            },
        })
    }

    /// Runs the actual original prefix and clock without renewing its origin.
    ///
    /// # Errors
    /// Preserves original currentness/deadline refusal and selected post debt.
    pub fn observe_current_once_v1(
        &mut self,
    ) -> Result<RawPairedClockSample, RootQ04OriginErrorV1> {
        match &mut self.original {
            LoanKind::Selected(original) => original.observe_current_once_v1().map_err(Into::into),
            LoanKind::Ordinary(original) => {
                original.observe_prefix_once_v1()?;
                original
                    .observe_original_clock_once_v1()
                    .map_err(Into::into)
            }
        }
    }

    /// Samples only the same actual original paired-clock interval.
    ///
    /// # Errors
    /// Preserves native clock failure or the unchanged original65s deadline.
    pub fn observe_original_clock_once_v1(
        &mut self,
    ) -> Result<RawPairedClockSample, RootQ04OriginErrorV1> {
        match &mut self.original {
            LoanKind::Selected(original) => original
                .observe_original_clock_once_v1()
                .map_err(Into::into),
            LoanKind::Ordinary(original) => original
                .observe_original_clock_once_v1()
                .map_err(Into::into),
        }
    }

    /// Qualifies the actual received subject under its original peer.
    ///
    /// # Errors
    /// Preserves native subject refusal. Ordinary retains its existing peer-
    /// only subject frontier; its enclosing current bookends remain separate.
    pub fn observe_subject_once_v1(
        &mut self,
        chunk: &UnixStreamSubjectChunk,
    ) -> Result<(), RootQ04OriginErrorV1> {
        match &mut self.original {
            LoanKind::Selected(original) => original
                .observe_subject_once_v1(chunk)
                .map(|_| ())
                .map_err(Into::into),
            LoanKind::Ordinary(original) => {
                original.observe_subject_once_v1(chunk).map_err(Into::into)
            }
        }
    }
    /// Attempts only the independently owed ordinary startup post.
    ///
    /// # Errors
    /// Preserves ordinary startup failure and refuses selected purpose.
    pub fn observe_ordinary_startup_post_once_v1(&self) -> Result<(), RootQ04OriginErrorV1> {
        match &self.original {
            LoanKind::Ordinary(original) => original.observe_startup_once_v1().map_err(Into::into),
            LoanKind::Selected(_) => Err(RootQ04OriginErrorV1::Purpose),
        }
    }

    /// Attempts only the independently owed ordinary Controller peer post.
    ///
    /// # Errors
    /// Preserves original peer failure and refuses selected purpose.
    pub fn observe_ordinary_peer_post_once_v1(&self) -> Result<(), RootQ04OriginErrorV1> {
        match &self.original {
            LoanKind::Ordinary(original) => original.observe_peer_once_v1().map_err(Into::into),
            LoanKind::Selected(_) => Err(RootQ04OriginErrorV1::Purpose),
        }
    }

    /// Attempts only the independently owed ordinary receive-queue post.
    ///
    /// # Errors
    /// Preserves native readiness failure and refuses selected purpose.
    pub fn observe_ordinary_queue_post_once_v1(&self) -> Result<(), RootQ04OriginErrorV1> {
        match &self.original {
            LoanKind::Ordinary(original) => original.observe_queue_once_v1().map_err(Into::into),
            LoanKind::Selected(_) => Err(RootQ04OriginErrorV1::Purpose),
        }
    }

    /// Ends only the real ordinary socket at its original final frontier.
    ///
    /// # Errors
    /// Retains the actual shutdown result and refuses selected purpose.
    pub fn shutdown_ordinary_original_once_v1(&mut self) -> Result<(), RootQ04OriginErrorV1> {
        match &mut self.original {
            LoanKind::Ordinary(original) => {
                original.shutdown_original_once_v1().map_err(Into::into)
            }
            LoanKind::Selected(_) => Err(RootQ04OriginErrorV1::Purpose),
        }
    }

    /// Retires ordinary transport after its actual successful shutdown.
    ///
    /// The caller still requires its real typed Authority/target clearance.
    ///
    /// # Errors
    /// Refuses selected purpose or incomplete original shutdown.
    pub fn retire_ordinary_after_shutdown_once_v1(&mut self) -> Result<(), RootQ04OriginErrorV1> {
        match &mut self.original {
            LoanKind::Ordinary(original) => {
                original.retire_after_shutdown_once_v1().map_err(Into::into)
            }
            LoanKind::Selected(_) => Err(RootQ04OriginErrorV1::Purpose),
        }
    }
}

enum StreamKind<'native> {
    Selected(RootQ04NativeStreamLoanV1<'native>),
    Ordinary(&'native mut RetainedUnixStream),
}

/// Borrows the same native stream without detaching its owning origin.
pub struct RootQ04OriginNativeStreamLoanV1<'native> {
    stream: StreamKind<'native>,
}

impl RootQ04OriginNativeStreamLoanV1<'_> {
    /// Borrows the actual endpoint while its branch's native custody is held.
    #[must_use]
    pub fn stream_v1(&self) -> &RetainedUnixStream {
        match &self.stream {
            StreamKind::Selected(stream) => stream.stream_v1(),
            StreamKind::Ordinary(stream) => stream,
        }
    }

    /// Borrows the actual subject receiver while retaining the same origin.
    #[must_use]
    pub fn stream_mut_v1(&mut self) -> &mut RetainedUnixStream {
        match &mut self.stream {
            StreamKind::Selected(stream) => stream.stream_mut_v1(),
            StreamKind::Ordinary(stream) => stream,
        }
    }
}

enum CurrentKind<'origin, 'startup> {
    Selected(RootQ04InputCurrentLoanV1<'origin, 'startup>),
    Ordinary(&'origin mut RootQ04OrdinaryTransportOriginalV1<'startup>),
}

/// Retains the actual native prefix around the target's own name operation.
#[must_use = "finish the real prefix before returning or unwinding"]
pub struct RootQ04OriginInputCurrentLoanV1<'origin, 'startup> {
    original: CurrentKind<'origin, 'startup>,
}

impl RootQ04OriginInputCurrentLoanV1<'_, '_> {
    /// Finishes the original primary clock and any independently owed posts.
    ///
    /// # Errors
    /// Preserves original clock refusal or actual selected post failure.
    pub fn finish_once_v1(self) -> Result<RawPairedClockSample, RootQ04OriginErrorV1> {
        match self.original {
            CurrentKind::Selected(original) => original.finish_once_v1().map_err(Into::into),
            CurrentKind::Ordinary(original) => original
                .observe_original_clock_once_v1()
                .map_err(Into::into),
        }
    }

    /// Preserves target refusal while attempting only independently owed posts.
    ///
    /// Ordinary has no extra native post at this old primary frontier. The
    /// caller still retains and attempts its separate original resource posts.
    ///
    /// # Errors
    /// Always refuses; this negative entry cannot yield a current sample.
    pub fn finish_refused_once_v1(self) -> Result<(), RootQ04OriginErrorV1> {
        match self.original {
            CurrentKind::Selected(original) => {
                original.finish_refused_once_v1().map_err(Into::into)
            }
            CurrentKind::Ordinary(_) => Err(RootQ04OrdinaryTransportErrorV1::ChangedCut.into()),
        }
    }

    /// Reports only the independently owed negative native posts.
    ///
    /// Ordinary owes none at this primary target-refusal frontier. Selected
    /// remains closed and supplies no current sample or settlement.
    ///
    /// # Errors
    /// Preserves only actual selected Root-post/final-clock failure or panic.
    pub fn finish_negative_posts_once_v1(self) -> Result<(), RootQ04OriginErrorV1> {
        match self.original {
            CurrentKind::Selected(original) => original.finish_negative_posts_once_v1().map_err(Into::into),
            CurrentKind::Ordinary(_) => Ok(()),
        }
    }
}
