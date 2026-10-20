//! Borrows the retained endpoint quote without reviving its endpoint identity.
use super::*;
use crate::protocol_snapshot::restored_settled17::current_facts::BorrowedMetadataFacts17;
use serde::{Serialize, Serializer, ser::SerializeStruct};
struct EndpointQuoteHistory17<'a>(&'a PacketEndpointRestoreAllocation);
impl PacketEndpointRestoreAllocation {
    pub(crate) fn borrowed_settled_history_data(
        &self,
        policy: &Rc<crate::reference_packet::Native5Policy>,
    ) -> Result<impl Serialize + '_, ProviderError> {
        self.authenticate_original(policy)?;
        Ok(EndpointQuoteHistory17(self))
    }
    pub(crate) fn observe_settled_history_metadata_data(
        &self,
        observer: &mut MetadataObserver<'_>,
    ) -> Result<(), ProviderError> {
        self.authenticate_original(&self.policy)?;
        let Self {
            creator,
            thread: _,
            policy,
            facts: _,
            startup_banks: _,
        } = self;
        observer.observe(creator)?;
        observer.shared_original(
            crate::retained_metadata::aliases::MetadataSharedKind::NativePolicy,
            policy.as_ref(),
        )
    }
}
impl Serialize for EndpointQuoteHistory17<'_> {
    fn serialize<S: Serializer>(&self, serializer: S) -> Result<S::Ok, S::Error> {
        let PacketEndpointRestoreAllocation {
            creator,
            thread: _,
            policy: _,
            facts,
            startup_banks,
        } = self.0;
        let mut fields = serializer.serialize_struct("NativeEndpointRestoreQuote17", 6)?;
        fields.serialize_field("schema", "source-private.native-endpoint-restore-quote/17")?;
        fields.serialize_field("creator", creator)?;
        fields.serialize_field("thread_role", "same-original-native-thread-history-only")?;
        fields.serialize_field("policy_role", "native-policy")?;
        fields.serialize_field("facts", &BorrowedMetadataFacts17(facts))?;
        fields.serialize_field("startup_banks", startup_banks)?;
        fields.end()
    }
}
