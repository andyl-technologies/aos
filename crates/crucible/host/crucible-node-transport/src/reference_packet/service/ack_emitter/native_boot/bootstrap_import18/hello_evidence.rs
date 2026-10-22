//! Lends the complete physical Hello pair under the original admitted SDK lease.
//!
//! Role digests come from the actual journal and successful write progress.
//! Existing raw-journal parsed flags remain untouched: the enclosing root proves
//! original typed negotiation and publication through their own physical owners.
//! These Copy values carry correspondence only, without ACK or native permission.

use super::*;
use crate::client::OriginalNativePublicBirthChannel;
use crate::hello_frames::OriginalHelloFrameDigests;
use crate::native_hello::{OriginalNativeHelloPublication, RetainedOriginalNativeHelloExchange};

type Exchange = RetainedOriginalNativeHelloExchange<OriginalNativePublicBirthChannel>;

impl OriginalImport18RawBootstrap {
    /// Reads literal pair DATA inside an already held original operand loan.
    ///
    /// The enclosing composite loan supplies complete Host/SDK/input guards.
    /// This helper keeps physical publication and current authority checks and
    /// returns no permission or ownership of either frame.
    ///
    /// # Errors
    /// Refuses stale SDK/cut/channel or incomplete physical publication.
    pub(super) fn published_hello_frame_digests_under_operands_data(
        &self,
        operands: &super::bootstrap_operands::BootstrapAckOperands<'_>,
    ) -> Result<OriginalHelloFrameDigests, ProviderError> {
        operands.ensure_current_authority_data()?;
        self.authenticate_channel()?;
        let result = self
            .hello_exchange
            .borrow_data()?
            .as_ref()
            .ok_or_else(refused)?
            .with_exchange_data(|exchange| {
                self.hello_publication
                    .frame_digests_data(exchange, self.cut)
            });
        let terminal = self
            .authenticate_channel()
            .and_then(|()| operands.ensure_current_authority_data());
        let digests = result?;
        terminal?;
        Ok(digests)
    }

    /// Lends role-normalized literal digests after actual SDK admission/publication.
    ///
    /// The caller separately admits inspection and any subsequent serialization.
    /// Only Copy DATA returns. Both physical pairs and full enclosing SDK/input
    /// guards run around inspection under the same original cut and owners.
    ///
    /// # Errors
    /// Refuses incomplete/refused publication, stale original lease/custody,
    /// partial/changed literal frames, callback failure or terminal disagreement.
    pub(in super::super) fn with_published_hello_frame_digests_data<R: Copy>(
        &self,
        inspect: impl FnOnce(OriginalHelloFrameDigests) -> Result<R, ProviderError>,
    ) -> Result<R, ProviderError> {
        self.with_published_hello_body_data(|_| {
            let holder = self.hello_exchange.borrow_data()?;
            let exchange = holder.as_ref().ok_or_else(refused)?;
            let before = exchange.with_exchange_data(|exchange| {
                self.hello_publication
                    .frame_digests_data(exchange, self.cut)
            })?;

            let outcome = inspect(before);
            let terminal = exchange.with_exchange_data(|exchange| {
                self.hello_publication
                    .frame_digests_data(exchange, self.cut)
            });
            let result = outcome?;
            if terminal? != before {
                return Err(refused());
            }
            Ok(result)
        })
    }

    /// Names complete pair-loan controls beside independently funded inspection.
    ///
    /// # Errors
    /// Refuses checked overflow for the caller's concrete Copy result layout.
    pub(in super::super) fn published_hello_frame_digests_loan_counter_scratch_data<R: Copy>()
    -> Result<usize, ProviderError> {
        let base = Self::published_hello_body_loan_counter_scratch_data::<R>()?;
        let fields = [
            pair_counter_scratch_data(),
            size_of::<R>(),
            size_of::<R>(),
            size_of::<Result<R, ProviderError>>(),
            size_of::<Result<R, ProviderError>>(),
        ];
        fields.into_iter().try_fold(base, |sum, field| {
            sum.checked_add(field).ok_or_else(refused)
        })
    }
}

/// Names the concrete unit-result inspection window in the complete initial row.
pub(super) fn counter_scratch_data() -> usize {
    super::hello_publication::body_loan_fixed_counter_scratch_data()
        + size_of::<Result<(), ProviderError>>() * 4
        + pair_counter_scratch_data()
}

pub(super) fn pair_counter_scratch_data() -> usize {
    OriginalNativeHelloPublication::completed_frame_digests_counter_scratch_data::<
        OriginalNativePublicBirthChannel,
    >() + Exchange::exchange_loan_counter_scratch_data::<OriginalHelloFrameDigests>()
        + size_of::<&OriginalImport18RawBootstrap>() * 2
        + size_of::<&Exchange>()
        + size_of::<OriginalHelloFrameDigests>() * 3
        + size_of::<Result<OriginalHelloFrameDigests, ProviderError>>() * 3
        + size_of::<[usize; 5]>()
        + size_of::<std::array::IntoIter<usize, 5>>()
        + size_of::<usize>() * 2
        + size_of::<Option<usize>>()
        + size_of::<Result<usize, ProviderError>>()
}

fn refused() -> ProviderError {
    ProviderError::Correlation("original published Hello evidence refused")
}
