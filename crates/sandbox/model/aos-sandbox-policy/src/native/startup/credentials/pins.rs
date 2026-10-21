//! Admits the three distinct optional owner pins in their original check order.

use super::super::RootStartupJournalOriginalV1;
use super::binding::ensure_root_binding_unheld_v1;
use super::deployment::encode_signer_pins_v1;
use super::transaction::owner_pin_transaction;
use super::{RootStartupCredentialErrorV1 as ErrorV1, RootStartupCredentialWriterV1};
use crate::controller_readback::PinnedControllerHoldSignerV1;
use crate::journal_keys::{
    CACHE_PIN_KEY, CONTROLLER_HOLD_PIN_KEY, SIGNER_PINS_KEY, SOURCE_HOLD_PIN_KEY,
};
use aos_sandbox_ledger_replay::source_signer_data::source_hold_readback::PinnedSourceHoldReadbackSignerV1;
use aos_sandbox_protocol::cache_owner_readback::PinnedCacheOwnerReadbackSignerV1;
use ed25519_dalek::VerifyingKey;

impl RootStartupCredentialWriterV1<'_> {
    /// Admits the optional Cache pin through this same native writer.
    ///
    /// # Errors
    /// Preserves missing or changed state, key reuse, rotation and native refusals.
    pub fn admit_cache_pin(&mut self, credential: Option<&[u8]>) -> Result<(), ErrorV1> {
        let pins = self.admitted_signer_pins_v1()?;
        let deployment_generation = pins.deployment_generation;
        let deployment_key = &pins.deployment_key;
        let project_generation = pins.project_generation;
        let project_key = &pins.project_key;
        self.journal.journal_mut_v1()?;

        self.journal.admit_cache_pin_after_entry_v1(
            credential,
            deployment_generation,
            deployment_key,
            project_generation,
            project_key,
            self.original.as_ref(),
        )
    }

    /// Admits the optional Controller pin through this same native writer.
    ///
    /// # Errors
    /// Preserves missing or changed state, key reuse, rotation and native refusals.
    pub fn admit_controller_pin(&mut self, credential: Option<&[u8]>) -> Result<(), ErrorV1> {
        let pins = self.admitted_signer_pins_v1()?;
        let deployment_generation = pins.deployment_generation;
        let deployment_key = &pins.deployment_key;
        let project_generation = pins.project_generation;
        let project_key = &pins.project_key;
        self.journal.journal_mut_v1()?;

        self.journal.admit_controller_pin_after_entry_v1(
            credential,
            deployment_generation,
            deployment_key,
            project_generation,
            project_key,
            self.original.as_ref(),
        )
    }

    /// Admits the optional Source pin through this same native writer.
    ///
    /// # Errors
    /// Preserves missing or changed state, key reuse, rotation and native refusals.
    pub fn admit_source_pin(&mut self, credential: Option<&[u8]>) -> Result<(), ErrorV1> {
        let pins = self.admitted_signer_pins_v1()?;
        let deployment_generation = pins.deployment_generation;
        let deployment_key = &pins.deployment_key;
        let project_generation = pins.project_generation;
        let project_key = &pins.project_key;
        self.journal.journal_mut_v1()?;

        self.journal.admit_source_pin_after_entry_v1(
            credential,
            deployment_generation,
            deployment_key,
            project_generation,
            project_key,
            self.original.as_ref(),
        )
    }
}

impl RootStartupJournalOriginalV1 {
    pub(in crate::native::startup) fn admit_cache_pin_after_entry_v1(
        &mut self,
        credential: Option<&[u8]>,
        deployment_generation: u64,
        deployment_key: &VerifyingKey,
        project_generation: u64,
        project_key: &VerifyingKey,
        original: Option<&aos_sandbox_broker::receiving::RootJournalFinancialBorrowV1<'_>>,
    ) -> Result<(), ErrorV1> {
        let policy_pins = encode_signer_pins_v1(
            deployment_generation,
            deployment_key,
            project_generation,
            project_key,
        )
        .map_err(|_| ErrorV1::InvalidPin)?;

        let mut authority = self.credential_authority_after_entry_v1(original)?;
        ensure_root_binding_unheld_v1(&authority).map_err(|_| ErrorV1::StalePin)?;
        if authority.get(SIGNER_PINS_KEY)? != Some(policy_pins.as_slice()) {
            return Err(ErrorV1::StalePin);
        }
        let Some(credential) = credential else {
            return if authority.get(CACHE_PIN_KEY)?.is_none() {
                Ok(())
            } else {
                Err(ErrorV1::StalePin)
            };
        };
        let cache = PinnedCacheOwnerReadbackSignerV1::decode(credential)
            .map_err(|_| ErrorV1::InvalidPin)?;
        if cache.verifying_key() == deployment_key || cache.verifying_key() == project_key {
            return Err(ErrorV1::InvalidPin);
        }
        if let Some(controller_pin) = authority.get(CONTROLLER_HOLD_PIN_KEY)? {
            let controller = PinnedControllerHoldSignerV1::decode(controller_pin)
                .map_err(|_| ErrorV1::StalePin)?;
            if controller.verifying_key() == cache.verifying_key() {
                return Err(ErrorV1::InvalidPin);
            }
        }
        if let Some(source_pin) = authority.get(SOURCE_HOLD_PIN_KEY)? {
            let source = PinnedSourceHoldReadbackSignerV1::decode(source_pin)
                .map_err(|_| ErrorV1::StalePin)?;
            if source.verifying_key() == cache.verifying_key() {
                return Err(ErrorV1::InvalidPin);
            }
        }
        match authority.get(CACHE_PIN_KEY)? {
            Some(current) if current == credential => return Ok(()),
            Some(_) => return Err(ErrorV1::StalePin),
            None => {}
        }

        let transaction = owner_pin_transaction(
            b"aos.sandbox.policy-cache-readback-pin-transaction.v1\0",
            CACHE_PIN_KEY,
            credential,
        )?;
        authority.commit(&transaction)?;
        if authority.get(CACHE_PIN_KEY)? != Some(credential) {
            return Err(ErrorV1::StalePin);
        }
        Ok(())
    }

    pub(in crate::native::startup) fn admit_controller_pin_after_entry_v1(
        &mut self,
        credential: Option<&[u8]>,
        deployment_generation: u64,
        deployment_key: &VerifyingKey,
        project_generation: u64,
        project_key: &VerifyingKey,
        original: Option<&aos_sandbox_broker::receiving::RootJournalFinancialBorrowV1<'_>>,
    ) -> Result<(), ErrorV1> {
        let policy_pins = encode_signer_pins_v1(
            deployment_generation,
            deployment_key,
            project_generation,
            project_key,
        )
        .map_err(|_| ErrorV1::InvalidPin)?;
        let mut authority = self.credential_authority_after_entry_v1(original)?;
        ensure_root_binding_unheld_v1(&authority).map_err(|_| ErrorV1::StalePin)?;
        if authority.get(SIGNER_PINS_KEY)? != Some(policy_pins.as_slice()) {
            return Err(ErrorV1::StalePin);
        }
        let Some(credential) = credential else {
            return if authority.get(CONTROLLER_HOLD_PIN_KEY)?.is_none() {
                Ok(())
            } else {
                Err(ErrorV1::StalePin)
            };
        };
        let controller =
            PinnedControllerHoldSignerV1::decode(credential).map_err(|_| ErrorV1::InvalidPin)?;
        if controller.verifying_key() == deployment_key || controller.verifying_key() == project_key
        {
            return Err(ErrorV1::InvalidPin);
        }
        if let Some(cache_pin) = authority.get(CACHE_PIN_KEY)? {
            let cache = PinnedCacheOwnerReadbackSignerV1::decode(cache_pin)
                .map_err(|_| ErrorV1::StalePin)?;
            if cache.verifying_key() == controller.verifying_key() {
                return Err(ErrorV1::InvalidPin);
            }
        }
        if let Some(source_pin) = authority.get(SOURCE_HOLD_PIN_KEY)? {
            let source = PinnedSourceHoldReadbackSignerV1::decode(source_pin)
                .map_err(|_| ErrorV1::StalePin)?;
            if source.verifying_key() == controller.verifying_key() {
                return Err(ErrorV1::InvalidPin);
            }
        }
        match authority.get(CONTROLLER_HOLD_PIN_KEY)? {
            Some(current) if current == credential => return Ok(()),
            Some(_) => return Err(ErrorV1::StalePin),
            None => {}
        }

        let transaction = owner_pin_transaction(
            b"aos.sandbox.policy-controller-hold-pin-transaction.v1\0",
            CONTROLLER_HOLD_PIN_KEY,
            credential,
        )?;
        authority.commit(&transaction)?;
        if authority.get(CONTROLLER_HOLD_PIN_KEY)? != Some(credential) {
            return Err(ErrorV1::StalePin);
        }
        Ok(())
    }

    pub(in crate::native::startup) fn admit_source_pin_after_entry_v1(
        &mut self,
        credential: Option<&[u8]>,
        deployment_generation: u64,
        deployment_key: &VerifyingKey,
        project_generation: u64,
        project_key: &VerifyingKey,
        original: Option<&aos_sandbox_broker::receiving::RootJournalFinancialBorrowV1<'_>>,
    ) -> Result<(), ErrorV1> {
        let policy_pins = encode_signer_pins_v1(
            deployment_generation,
            deployment_key,
            project_generation,
            project_key,
        )
        .map_err(|_| ErrorV1::InvalidPin)?;

        let mut authority = self.credential_authority_after_entry_v1(original)?;
        ensure_root_binding_unheld_v1(&authority).map_err(|_| ErrorV1::StalePin)?;
        if authority.get(SIGNER_PINS_KEY)? != Some(policy_pins.as_slice()) {
            return Err(ErrorV1::StalePin);
        }
        let Some(credential) = credential else {
            return if authority.get(SOURCE_HOLD_PIN_KEY)?.is_none() {
                Ok(())
            } else {
                Err(ErrorV1::StalePin)
            };
        };
        let source = PinnedSourceHoldReadbackSignerV1::decode(credential)
            .map_err(|_| ErrorV1::InvalidPin)?;
        if source.verifying_key() == deployment_key || source.verifying_key() == project_key {
            return Err(ErrorV1::InvalidPin);
        }
        if let Some(controller_pin) = authority.get(CONTROLLER_HOLD_PIN_KEY)? {
            let controller = PinnedControllerHoldSignerV1::decode(controller_pin)
                .map_err(|_| ErrorV1::StalePin)?;
            if source.verifying_key() == controller.verifying_key() {
                return Err(ErrorV1::InvalidPin);
            }
        }
        if let Some(cache_pin) = authority.get(CACHE_PIN_KEY)? {
            let cache = PinnedCacheOwnerReadbackSignerV1::decode(cache_pin)
                .map_err(|_| ErrorV1::StalePin)?;
            if source.verifying_key() == cache.verifying_key() {
                return Err(ErrorV1::InvalidPin);
            }
        }
        match authority.get(SOURCE_HOLD_PIN_KEY)? {
            Some(current) if current == credential => return Ok(()),
            Some(_) => return Err(ErrorV1::StalePin),
            None => {}
        }

        let transaction = owner_pin_transaction(
            b"aos.sandbox.policy-source-hold-pin-transaction.v1\0",
            SOURCE_HOLD_PIN_KEY,
            credential,
        )?;
        authority.commit(&transaction)?;
        if authority.get(SOURCE_HOLD_PIN_KEY)? != Some(credential) {
            return Err(ErrorV1::StalePin);
        }
        Ok(())
    }
}
