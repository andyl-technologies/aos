//! Lends the actual completed Controller peer, held stream and current sample.
//!
//! The mechanical borrower preserves the existing native observation and
//! settlement bodies. Its caller independently owns purpose admission, quote,
//! stage, names and clock checks; this borrower grants none of them.

use std::error::Error as StdError;

use aos_linux_descriptors::unix_stream::RetainedUnixStream;

use super::{Error, RootSelectedControllerCurrentSampleV1, RootSelectedControllerPeerOriginalV1};

/// Borrows the same original peer and stream into an already reserved sample.
///
/// No history-service post, worker slot or clock is constructed. The actual
/// purpose owner must retain its existing lender and paid stage programme.
pub struct RootControllerCurrentBorrowerV1<'cut, 'startup> {
    sample: &'cut mut RootSelectedControllerCurrentSampleV1,
    peer: &'cut RootSelectedControllerPeerOriginalV1<'startup>,
    stream: &'cut RetainedUnixStream,
}

impl RootSelectedControllerCurrentSampleV1 {
    /// Borrows this actual sample with a completed native peer and held stream.
    ///
    /// No native observation or settlement runs at construction.
    ///
    /// # Errors
    /// Refuses an incomplete or failed original Controller qualifier.
    pub fn borrow_current_original_v1<'cut, 'startup>(
        &'cut mut self,
        peer: &'cut RootSelectedControllerPeerOriginalV1<'startup>,
        stream: &'cut RetainedUnixStream,
    ) -> Result<RootControllerCurrentBorrowerV1<'cut, 'startup>, Error> {
        peer.require_completed()?;
        Ok(RootControllerCurrentBorrowerV1 { sample: self, peer, stream })
    }
}

impl RootControllerCurrentBorrowerV1<'_, '_> {
    /// Runs the sole original native/PID1 current observation into this sample.
    ///
    /// # Errors
    /// Retains and refuses the same native, identity, property or image failure
    /// as the original peer method, including repeated sample entry.
    pub fn observe_once_v1(&mut self) -> Result<(), Error> {
        self.peer.observe_prearmed_current_into_v1(self.stream, self.sample)
    }

    /// Settles this same sample after the caller's independent Root posts.
    ///
    /// # Errors
    /// Refuses the original failed, incomplete or repeated settlement.
    pub fn settle_after_root_post_once_v1(&mut self) -> Result<(), Error> {
        self.sample.settle_after_root_post_once_v1()
    }

    /// Borrows this same sample's earliest actual failure without observation.
    #[must_use]
    pub fn failure_v1(&self) -> Option<&(dyn StdError + 'static)> {
        self.sample.failure()
    }

    /// Borrows the property diagnostic selected by this sample's first cause.
    #[must_use]
    pub fn property_failure_view_v1(
        &self,
    ) -> Option<aos_systemd_client::FixedPid1PropertyFailureViewV1<'_>> {
        self.sample.property_failure_view_v1()
    }

    /// Measures only the new borrow and forwarding controls before construction.
    ///
    /// Actual sample, archive, native buffers and purpose-owner storage remain
    /// in their original suppliers. The genuine purpose entry must consume this
    /// quote once; it does not confer admission or debit any account itself.
    #[must_use]
    pub fn additional_control_bytes_v1() -> Option<usize> {
        use std::mem::size_of;

        size_of::<Self>().checked_mul(3)?
            .checked_add(size_of::<Result<Self, Error>>().checked_mul(3)?)?
            .checked_add(size_of::<(
                &mut RootSelectedControllerCurrentSampleV1,
                &RootSelectedControllerPeerOriginalV1<'_>,
                &RetainedUnixStream,
            )>().checked_mul(3)?)?
            .checked_add(size_of::<Result<(), Error>>().checked_mul(6)?)?
            .checked_add(size_of::<&mut Self>().checked_mul(6)?)?
            .checked_add(size_of::<&Self>().checked_mul(6)?)?
            .checked_add(size_of::<Option<&(dyn StdError + 'static)>>().checked_mul(3)?)?
            .checked_add(size_of::<Option<aos_systemd_client::FixedPid1PropertyFailureViewV1<'_>>>()
                .checked_mul(3)?)
    }
}
