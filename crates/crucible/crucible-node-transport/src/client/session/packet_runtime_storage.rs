//! Lends the actual installed Connection codec to future packet funding.
//!
//! No arbitrary BodySchemaVerifier callback or replacement Session can supply
//! this row. The original Connection authenticates its concrete codec owner.

use super::*;
use std::mem::size_of;

impl ClientSession {
    pub(in crate::client) fn packet_runtime_connection_storage_data(
        &self,
        owner: &crate::connection::OriginalRetainedSupervisor,
        maximum: usize,
    ) -> Result<[usize; 3], ProviderError> {
        if self.original_response_loss.is_some() {
            return Err(ProviderError::Conflict(
                "packet runtime response-loss callback",
            ));
        }
        let mut row = self
            .connection
            .original_packet_runtime_connection_storage_data(owner, maximum)?;
        row[2] = row[2]
            .checked_add(Self::packet_runtime_connection_wrapper_counter_scratch_data())
            .ok_or(ProviderError::ResourceExhausted(
                "packet runtime Session connection counter",
            ))?;
        let total = row.into_iter().try_fold(0usize, |total, value| {
            total
                .checked_add(value)
                .ok_or(ProviderError::ResourceExhausted(
                    "packet runtime Session connection row",
                ))
        })?;
        if total > maximum {
            return Err(ProviderError::ResourceExhausted(
                "packet runtime Session connection row",
            ));
        }
        Ok(row)
    }

    pub(in crate::client) fn packet_runtime_connection_counter_scratch_data() -> usize {
        Connection::<DeadlineStream>::original_packet_runtime_connection_counter_scratch_data()
            + Self::packet_runtime_connection_wrapper_counter_scratch_data()
    }

    fn packet_runtime_connection_wrapper_counter_scratch_data() -> usize {
        size_of::<&Self>()
            + size_of::<&crate::connection::OriginalRetainedSupervisor>()
            + size_of::<[usize; 3]>()
            + size_of::<std::array::IntoIter<usize, 3>>()
            + size_of::<Result<[usize; 3], ProviderError>>()
            + size_of::<Result<usize, ProviderError>>()
            + size_of::<Option<usize>>()
            + 3 * size_of::<usize>()
    }

    pub(in crate::client) fn packet_runtime_codec_storage_data(
        &self,
        maximum: usize,
    ) -> Result<[usize; 2], ProviderError> {
        let mut row = self
            .connection
            .original_packet_runtime_codec_storage_data(maximum)?;
        row[1] = row[1]
            .checked_add(Self::packet_runtime_codec_wrapper_counter_scratch_data())
            .ok_or(ProviderError::ResourceExhausted(
                "packet runtime Session counter",
            ))?;
        if row[0]
            .checked_add(row[1])
            .is_none_or(|total| total > maximum)
        {
            return Err(ProviderError::ResourceExhausted(
                "packet runtime Session row",
            ));
        }
        Ok(row)
    }

    pub(in crate::client) fn packet_runtime_codec_counter_scratch_data() -> usize {
        Connection::<DeadlineStream>::original_packet_runtime_codec_counter_scratch_data()
            + Self::packet_runtime_codec_wrapper_counter_scratch_data()
    }

    fn packet_runtime_codec_wrapper_counter_scratch_data() -> usize {
        size_of::<&Self>()
            + size_of::<[usize; 2]>()
            + size_of::<Result<[usize; 2], ProviderError>>()
            + size_of::<Result<usize, ProviderError>>()
            + size_of::<Option<usize>>()
            + size_of::<usize>()
    }
}

#[cfg(all(test, unix))]
mod tests {
    use super::*;
    use crate::connection::ConnectionIncident;
    use std::cell::Cell;

    #[test]
    fn original_connection_quote_checks_the_whole_row_and_exact_supervisor() {
        let (_handshake, session, owner, _witness, _peer) =
            ClientSession::restoration_retained_fixture();
        let (_other_handle, other_owner) =
            crate::connection::OriginalRetainedSupervisor::reserve().unwrap();
        let row = session
            .packet_runtime_connection_storage_data(&owner, usize::MAX)
            .unwrap();
        let requested = row.into_iter().sum::<usize>();

        assert!(row[0] > 0);
        assert_eq!(row[1], 0);
        assert_eq!(
            row[2],
            ClientSession::packet_runtime_connection_counter_scratch_data()
        );
        assert_eq!(
            session
                .packet_runtime_connection_storage_data(&owner, requested)
                .unwrap(),
            row
        );
        assert!(
            session
                .packet_runtime_connection_storage_data(&owner, requested - 1)
                .is_err()
        );
        assert!(
            session
                .packet_runtime_connection_storage_data(&other_owner, usize::MAX)
                .is_err()
        );
        assert!(owner.is_empty_data().unwrap());
        assert!(other_owner.is_empty_data().unwrap());
    }

    #[test]
    fn revoked_funding_query_cannot_allocate_a_containment_incident() {
        let (mut handshake, session, owner, _witness, _peer) =
            ClientSession::restoration_retained_fixture();
        session
            .packet_runtime_connection_storage_data(&owner, usize::MAX)
            .unwrap();

        handshake.contain();

        assert!(
            session
                .packet_runtime_connection_storage_data(&owner, usize::MAX)
                .is_err()
        );
        assert!(owner.is_empty_data().unwrap());
    }

    #[test]
    fn original_codec_quote_uses_the_installed_controller_and_live_registration() {
        let (mut handshake, session, _owner, _witness, _peer) =
            ClientSession::restoration_retained_fixture();
        let row = session
            .packet_runtime_codec_storage_data(usize::MAX)
            .unwrap();
        let requested = row[0].checked_add(row[1]).unwrap();

        assert_eq!(
            row[1],
            ClientSession::packet_runtime_codec_counter_scratch_data()
        );
        assert_eq!(
            session
                .packet_runtime_codec_storage_data(requested)
                .unwrap(),
            row
        );
        assert!(
            session
                .packet_runtime_codec_storage_data(requested - 1)
                .is_err()
        );

        handshake.contain();

        assert!(
            session
                .packet_runtime_codec_storage_data(usize::MAX)
                .is_err()
        );
    }

    #[test]
    fn arbitrary_schema_callbacks_cannot_supply_a_fixed_codec_quote() {
        let (_handshake, authority) = crate::handshake::tests::controller_authority(true).unwrap();
        let calls = Rc::new(Cell::new(0));
        let (session, _peer) = ClientSession::controller_fixture(
            authority,
            Rc::new(Supervisor),
            Rc::new(Callback(calls.clone())),
        )
        .unwrap();

        assert!(
            session
                .packet_runtime_codec_storage_data(usize::MAX)
                .is_err()
        );
        assert_eq!(calls.get(), 0);
    }

    struct Supervisor;

    impl ConnectionSupervisor for Supervisor {
        fn quarantine(&self, _incident: ConnectionIncident) {}
    }

    struct Callback(Rc<Cell<usize>>);

    impl BodySchemaVerifier for Callback {
        fn verify(
            &self,
            _authority: &ConnectionAuthority,
            _envelope: &Envelope,
            _body: &ReceivedBody,
        ) -> Result<(), ProviderError> {
            self.0.set(self.0.get() + 1);
            Ok(())
        }
    }
}
