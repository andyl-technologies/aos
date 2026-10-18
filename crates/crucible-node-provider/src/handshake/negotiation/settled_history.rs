//! Borrows the complete actual registration authority as historical DATA.
//!
//! ```text
//! {schema, gate_role, epoch_role, saved_epoch, observed_epoch, gate_poisoned,
//!  connection, session, incarnation, limits, features, envelope_extensions,
//!  extensions}
//! ```
//!
//! The enclosing owner records actual shared aliases and checks relative parent
//! identity. No portable epoch, role or field can construct a live authority.

use super::*;
use serde::{Serialize, Serializer, ser::SerializeStruct};

struct AuthorityHistory<'a> {
    authority: &'a ConnectionAuthority,
    observed_epoch: u64,
    gate_poisoned: bool,
}

impl Serialize for AuthorityHistory<'_> {
    fn serialize<S: Serializer>(&self, serializer: S) -> Result<S::Ok, S::Error> {
        let ConnectionAuthority {
            shared_epoch: _,
            registration_gate: _,
            epoch,
            connection,
            session,
            incarnation,
            limits,
            features,
            envelope_extensions,
            extensions,
        } = self.authority;
        let mut state = serializer.serialize_struct("RegistrationAuthorityHistory", 13)?;
        state.serialize_field("schema", "source-private.connection-authority/17")?;
        state.serialize_field("gate_role", "registrar-gate")?;
        state.serialize_field("epoch_role", "registrar-epoch")?;
        state.serialize_field("saved_epoch", epoch)?;
        state.serialize_field("observed_epoch", &self.observed_epoch)?;
        state.serialize_field("gate_poisoned", &self.gate_poisoned)?;
        state.serialize_field("connection", connection)?;
        state.serialize_field("session", session)?;
        state.serialize_field("incarnation", incarnation)?;
        state.serialize_field("limits", limits)?;
        state.serialize_field("features", features)?;
        state.serialize_field("envelope_extensions", envelope_extensions)?;
        state.serialize_field("extensions", extensions)?;
        state.end()
    }
}

impl ConnectionAuthority {
    /// Borrows every retained authority field and samples its historical gate facts.
    ///
    /// Sampling does not lock the mutex, require a live epoch, clone handles or
    /// renew a deadline. The owning capture boundary separately authenticates
    /// currentness and records the actual gate/epoch/extension shared edges.
    pub(crate) fn borrowed_settled_history_data(&self) -> impl Serialize + '_ {
        AuthorityHistory {
            authority: self,
            observed_epoch: self.shared_epoch.load(Ordering::Acquire),
            gate_poisoned: self.registration_gate.is_poisoned(),
        }
    }

    /// Reports the defining fixed sample and exhaustive borrowed field views.
    ///
    /// Dynamic strings, extensions, tree/alias banks and serialized output remain
    /// independent terms in the enclosing graph; this getter creates no credit.
    pub(crate) fn settled_history_counter_scratch_data() -> usize {
        use std::mem::{size_of, size_of_val};

        let terms = [
            size_of::<Self>(),
            size_of::<&Self>(),
            size_of::<AuthorityHistory<'_>>(),
            size_of::<&AuthorityHistory<'_>>(),
            size_of::<u64>(),
            size_of::<bool>(),
            field_view_bytes(|value: &'static ConnectionAuthority| {
                let ConnectionAuthority {
                    shared_epoch,
                    registration_gate,
                    epoch,
                    connection,
                    session,
                    incarnation,
                    limits,
                    features,
                    envelope_extensions,
                    extensions,
                } = value;
                (
                    shared_epoch,
                    registration_gate,
                    epoch,
                    connection,
                    session,
                    incarnation,
                    limits,
                    features,
                    envelope_extensions,
                    extensions,
                )
            }),
            field_view_bytes(|value: &'static ConnectionAuthority| {
                let ConnectionAuthority {
                    shared_epoch: _,
                    registration_gate: _,
                    epoch,
                    connection,
                    session,
                    incarnation,
                    limits,
                    features,
                    envelope_extensions,
                    extensions,
                } = value;
                (
                    epoch,
                    connection,
                    session,
                    incarnation,
                    limits,
                    features,
                    envelope_extensions,
                    extensions,
                )
            }),
        ];
        size_of_val(&terms)
            + size_of::<std::array::IntoIter<usize, 8>>()
            + terms.into_iter().sum::<usize>()
    }
}

const fn field_view_bytes<T: 'static, U>(_: fn(&'static T) -> U) -> usize {
    std::mem::size_of::<U>()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn actual_negotiated_authority_retains_saved_and_revoked_epoch_data()
    -> Result<(), ProviderError> {
        // Keep the real registrar until the deliberate epoch revocation below.
        let (_registrar, authority) = crate::handshake::tests::authority();
        authority.ensure_live()?;
        let saved = authority.epoch;
        authority.shared_epoch.fetch_add(1, Ordering::AcqRel);
        assert!(authority.ensure_live().is_err());
        let held = authority.registration_gate.try_lock().map_err(|_| {
            ProviderError::Correlation("authority history fixture lock unavailable")
        })?;

        let value =
            serde_json::to_value(authority.borrowed_settled_history_data()).map_err(|_| {
                ProviderError::Correlation("authority history fixture serialization failed")
            })?;
        assert_eq!(value["schema"], "source-private.connection-authority/17");
        assert_eq!(value["saved_epoch"], saved);
        assert_eq!(value["observed_epoch"], saved + 1);
        assert_eq!(value["gate_poisoned"], false);
        assert_eq!(value.as_object().map(|fields| fields.len()), Some(13));
        assert_eq!(
            value["connection"].as_str(),
            Some(authority.connection.as_str())
        );
        assert_eq!(value["session"].as_str(), Some(authority.session.as_str()));
        assert_eq!(
            value["incarnation"].as_str(),
            Some(authority.incarnation.as_str())
        );
        drop(held);
        assert!(authority.ensure_live().is_err());
        Ok(())
    }
}
