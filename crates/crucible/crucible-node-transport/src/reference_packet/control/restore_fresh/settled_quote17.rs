//! Borrows all actual fresh Control quote fields without creating allocation credit.
use super::*;
use crate::protocol_snapshot::restored_settled17::current_facts::BorrowedMetadataFacts17;
use serde::{Serialize, Serializer, ser::SerializeStruct};
struct ControlQuoteHistory17<'a>(&'a PacketFreshRestoreControlAllocation);
impl PacketFreshRestoreControlAllocation {
    pub(crate) fn borrowed_settled_history_data(
        &self,
        policy: &Rc<crate::reference_packet::Native5Policy>,
    ) -> Result<impl Serialize + '_, ProviderError> {
        self.authenticate_original(policy)?;
        Ok(ControlQuoteHistory17(self))
    }
    pub(crate) fn observe_settled_history_metadata_data(
        &self,
        observer: &mut MetadataObserver<'_>,
    ) -> Result<(), ProviderError> {
        self.authenticate_original(&self.policy)?;
        let Self {
            creator,
            identity,
            policy,
            facts: _,
            endpoint,
            gate,
        } = self;
        observer.observe(creator)?;
        use crate::retained_metadata::aliases::MetadataSharedKind;
        observer.shared_original(MetadataSharedKind::NativeControlIdentity, identity.as_ref())?;
        observer.shared_original(MetadataSharedKind::NativePolicy, policy.as_ref())?;
        endpoint.observe_settled_history_metadata_data(observer)?;
        observer.observe(gate)
    }
}
impl Serialize for ControlQuoteHistory17<'_> {
    fn serialize<S: Serializer>(&self, serializer: S) -> Result<S::Ok, S::Error> {
        let PacketFreshRestoreControlAllocation {
            creator,
            identity: _,
            policy,
            facts,
            endpoint,
            gate,
        } = self.0;
        let mut fields = serializer.serialize_struct("NativeControlRestoreQuote17", 7)?;
        fields.serialize_field("schema", "source-private.native-control-restore-quote/17")?;
        fields.serialize_field("creator", creator)?;
        fields.serialize_field("control_identity_role", "current-native-control-identity")?;
        fields.serialize_field("policy_role", "native-policy")?;
        fields.serialize_field("facts", &BorrowedMetadataFacts17(facts))?;
        fields.serialize_field(
            "endpoint",
            &endpoint
                .borrowed_settled_history_data(policy)
                .map_err(serde::ser::Error::custom)?,
        )?;
        fields.serialize_field("gate", gate)?;
        fields.end()
    }
}
