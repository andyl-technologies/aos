//! Retains exact native Blob DATA fields in the caller's typed attempt.

use super::*;
/// Owns the actual optional retirement receipt while its suffix is checked.
#[derive(Default)]
pub(super) struct RetirementReadAttempt {
    completed: Option<Option<BlobRetirement>>,
    owner: Option<Id>,
    owner_attempt: <Id as Native17Build>::Attempt,
    receipt: Option<ContentRef>,
    receipt_attempt: <ContentRef as Native17Build>::Attempt,
}
impl RetirementReadAttempt {
    pub(super) fn read_into_data(
        &mut self,
        input: &[u8],
        ledger: &mut Ledger<'_, '_, '_>,
    ) -> Result<(), ProviderError> {
        let mut fields = Fields::array(input)?;
        let kind = plain_string(next(&mut fields)?)?;
        let owner = next(&mut fields)?;
        let receipt = next(&mut fields)?;
        match kind {
            "none" | "abandon-inert" => {
                if owner != b"null" || receipt != b"null" {
                    return Err(invalid());
                }
                fields.finish()?;
                self.completed = Some(if kind == "none" {
                    None
                } else {
                    Some(BlobRetirement::AbandonInert)
                });
            }
            "operation" => {
                if owner == b"null" || receipt == b"null" {
                    return Err(invalid());
                }
                owned::<Id>(owner, ledger, &mut self.owner_attempt, &mut self.owner)?;
                owned::<ContentRef>(
                    receipt,
                    ledger,
                    &mut self.receipt_attempt,
                    &mut self.receipt,
                )?;
                fields.finish()?;
                if self.owner.is_none() || self.receipt.is_none() {
                    return Err(invalid());
                }
                self.completed = Some(Some(BlobRetirement::Operation {
                    owner: self.owner.take().ok_or_else(invalid)?,
                    receipt: self.receipt.take().ok_or_else(invalid)?,
                }));
            }
            "durable-store" => {
                if owner != b"null" || receipt == b"null" {
                    return Err(invalid());
                }
                owned::<ContentRef>(
                    receipt,
                    ledger,
                    &mut self.receipt_attempt,
                    &mut self.receipt,
                )?;
                fields.finish()?;
                self.completed = Some(Some(BlobRetirement::DurableStore {
                    receipt: self.receipt.take().ok_or_else(invalid)?,
                }));
            }
            _ => return Err(invalid()),
        }
        Ok(())
    }
    pub(super) fn preflight_data(
        input: &[u8],
        ledger: &mut Ledger<'_, '_, '_>,
    ) -> Result<(), ProviderError> {
        let mut fields = Fields::array(input)?;
        let kind = plain_string(next(&mut fields)?)?;
        let owner = next(&mut fields)?;
        let receipt = next(&mut fields)?;
        match kind {
            "none" | "abandon-inert" if owner == b"null" && receipt == b"null" => (),
            "operation" if owner != b"null" && receipt != b"null" => {
                Id::preflight_data(owner, ledger)?;
                ContentRef::preflight_data(receipt, ledger)?;
            }
            "durable-store" if owner == b"null" && receipt != b"null" => {
                ContentRef::preflight_data(receipt, ledger)?
            }
            _ => return Err(invalid()),
        }
        fields.finish()
    }
    pub(super) fn take_output_data(&mut self) -> Option<Option<BlobRetirement>> {
        self.completed.take()
    }
    pub(super) fn output_data(&self) -> Option<&Option<BlobRetirement>> {
        self.completed.as_ref()
    }
    pub(super) fn observe_attempt_data(
        &self,
        observer: &mut MetadataObserver<'_>,
    ) -> Result<(), ProviderError> {
        if let Some(value) = &self.completed {
            observe_retirement(value, observer)?;
        }
        if let Some(value) = &self.owner {
            Id::observe_output_data(value, observer)?;
        }
        Id::observe_attempt_data(&self.owner_attempt, observer)?;
        if let Some(value) = &self.receipt {
            ContentRef::observe_output_data(value, observer)?;
        }
        ContentRef::observe_attempt_data(&self.receipt_attempt, observer)
    }
}
pub(crate) fn observe_retirement(
    value: &Option<BlobRetirement>,
    observer: &mut MetadataObserver<'_>,
) -> Result<(), ProviderError> {
    match value {
        Some(BlobRetirement::Operation { owner, receipt }) => {
            Id::observe_output_data(owner, observer)?;
            ContentRef::observe_output_data(receipt, observer)
        }
        Some(BlobRetirement::DurableStore { receipt }) => {
            ContentRef::observe_output_data(receipt, observer)
        }
        Some(BlobRetirement::AbandonInert) | None => Ok(()),
    }
}
