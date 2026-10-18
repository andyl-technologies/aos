//! Borrows every actual service quote field under its enclosing current Boot.
use super::*;
use crate::protocol_snapshot::restored_settled17::current_facts::BorrowedMetadataFacts17;
use serde::{Serialize, Serializer, ser::SerializeStruct};
struct QuoteHistory17<'a>(&'a NativeRestoreServiceAllocationQuote);
impl NativeRestoreServiceAllocationQuote {
    pub(crate) fn borrowed_settled_history_data<'a>(
        &'a self,
        policy: &Rc<crate::reference_packet::Native5Policy>,
        boot: &Rc<RefCell<NativeAckBoot>>,
    ) -> Result<impl Serialize + 'a, ProviderError> {
        if self.creator != std::process::id()
            || self.thread != std::thread::current().id()
            || !Rc::ptr_eq(&self.policy, policy)
            || !Rc::ptr_eq(&self.boot, boot)
        {
            return Err(ProviderError::Correlation(
                "current17 service quote parent differs",
            ));
        }
        Ok(QuoteHistory17(self))
    }
    pub(crate) fn observe_settled_history_metadata_data(
        &self,
        boot: &Rc<RefCell<NativeAckBoot>>,
        observer: &mut MetadataObserver<'_>,
    ) -> Result<(), ProviderError> {
        if self.creator != std::process::id()
            || self.thread != std::thread::current().id()
            || !Rc::ptr_eq(&self.boot, boot)
        {
            return Err(ProviderError::Correlation(
                "current17 service quote origin differs",
            ));
        }
        let Self {
            creator,
            thread: _,
            boot,
            policy,
            cut: _,
            facts: _,
        } = self;
        observer.observe(creator)?;
        observer.shared_original(MetadataSharedKind::NativeBoot, boot.as_ref())?;
        observer.shared_original(MetadataSharedKind::NativePolicy, policy.as_ref())
    }
}
impl Serialize for QuoteHistory17<'_> {
    fn serialize<S: Serializer>(&self, serializer: S) -> Result<S::Ok, S::Error> {
        let NativeRestoreServiceAllocationQuote {
            creator,
            thread: _,
            boot: _,
            policy: _,
            cut: _,
            facts,
        } = self.0;
        let mut fields = serializer.serialize_struct("NativeServiceRestoreQuote17", 7)?;
        fields.serialize_field("schema", "source-private.native-service-restore-quote/17")?;
        fields.serialize_field("creator", creator)?;
        fields.serialize_field("thread_role", "same-original-native-thread-history-only")?;
        fields.serialize_field("boot_role", "native-boot")?;
        fields.serialize_field("policy_role", "native-policy")?;
        fields.serialize_field("cut_role", "historical-operational-deadline")?;
        fields.serialize_field("facts", &BorrowedMetadataFacts17(facts))?;
        fields.end()
    }
}
