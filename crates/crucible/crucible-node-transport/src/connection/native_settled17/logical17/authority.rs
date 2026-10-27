//! Borrows complete registration lineage without rebuilding physical authority.

use super::bytes::{boolean, field, next};
use crate::ProviderError;
use crate::protocol_snapshot::owned11::typed::{Fields, invalid, plain_string, unsigned};

#[derive(Clone, Copy)]
pub(crate) struct BorrowedAuthority17Lineage<'a> {
    pub(crate) encoded: &'a [u8],
    pub(crate) connection: &'a [u8],
    pub(crate) session: &'a [u8],
    pub(crate) incarnation: &'a [u8],
    pub(crate) saved_epoch: u64,
    pub(crate) observed_epoch: u64,
    pub(crate) gate_poisoned: bool,
    pub(crate) limits: &'a [u8],
    pub(crate) features: &'a [u8],
    pub(crate) envelope_extensions: &'a [u8],
    pub(crate) extensions: &'a [u8],
}

impl<'a> BorrowedAuthority17Lineage<'a> {
    pub(crate) fn read(input: &'a [u8]) -> Result<Self, ProviderError> {
        let mut fields = Fields::object(input)?;
        if plain_string(fields.named("schema")?)? != "source-private.connection-authority/17"
            || plain_string(fields.named("gate_role")?)? != "registrar-gate"
            || plain_string(fields.named("epoch_role")?)? != "registrar-epoch"
        {
            return Err(invalid());
        }
        let saved_epoch = unsigned(fields.named("saved_epoch")?)?;
        let observed_epoch = unsigned(fields.named("observed_epoch")?)?;
        let gate_poisoned = boolean(fields.named("gate_poisoned")?)?;
        let connection = fields.named("connection")?;
        let session = fields.named("session")?;
        let incarnation = fields.named("incarnation")?;
        let limits = fields.named("limits")?;
        let features = fields.named("features")?;
        let envelope_extensions = fields.named("envelope_extensions")?;
        let extensions = fields.named("extensions")?;
        fields.finish()?;
        Ok(Self {
            encoded: input,
            connection,
            session,
            incarnation,
            saved_epoch,
            observed_epoch,
            gate_poisoned,
            limits,
            features,
            envelope_extensions,
            extensions,
        })
    }

    pub(crate) fn same_registration(self, other: Self) -> Result<(), ProviderError> {
        // Both are the same defining serializer, so exact full encoded equality
        // also preserves all negotiated limits and selected extension fields.
        if self.encoded != other.encoded {
            return Err(invalid());
        }
        Ok(())
    }

    pub(crate) fn require_live_history(self) -> Result<(), ProviderError> {
        if self.saved_epoch != self.observed_epoch || self.gate_poisoned {
            return Err(invalid());
        }
        Ok(())
    }

    pub(crate) fn authenticate_registrar(self, input: &[u8]) -> Result<(), ProviderError> {
        let mut outer = Fields::array(input)?;
        if plain_string(next(&mut outer)?)? != "source-private.original-extension-negotiation/11" {
            return Err(invalid());
        }
        let registrar = next(&mut outer)?;
        let mut installation = Fields::array(field(registrar, "installation")?)?;
        if next(&mut installation)? != self.session
            || next(&mut installation)? != self.incarnation
            || field(registrar, "current_connection")? != self.connection
            || super::bytes::quoted(field(registrar, "epoch")?)? != self.saved_epoch
            || super::bytes::quoted(field(registrar, "shared_epoch")?)? != self.observed_epoch
            || boolean(field(registrar, "registration_gate_poisoned")?)? != self.gate_poisoned
            || field(registrar, "selected_features")? != self.features
        {
            return Err(invalid());
        }
        next(&mut outer)?;
        next(&mut outer)?;
        if next(&mut outer)? != self.extensions {
            return Err(invalid());
        }
        outer.finish()
    }
}
