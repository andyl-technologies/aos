//! Reads only explicitly listed inline enums, arrays and source allocation rows.

use super::current_contracts::CurrentField17;
use super::{current_actions::CurrentCaptureStage17, current_suffix::CurrentAttemptStage17};
use crate::bodies::{BoundaryPolicy, RetirementDisposition};
use crate::reference_packet::service::restored_settled_capture::upload::PacketRestoredSettledCaptureUploadOrdinal;
use crate::{
    ProviderError,
    protocol_snapshot::owned11::typed::{Fields, Ledger, invalid, plain_string},
    reference_packet::service::{
        complete_restore::activation::{
            PacketRestorationActivationPhase, upload::PacketRestorationActivationUploadRole,
        },
        native_startup::PacketNativeStartupAllocationRow,
    },
    retained_metadata::MetadataObserver,
};

pub(crate) trait InlineEnum17: Sized {
    fn read_inline(input: &[u8]) -> Result<Self, ProviderError>;
}

macro_rules! inline_enum17 {
    ($ty:ty {$($text:literal=>$variant:ident),+ $(,)?})=>{
        impl InlineEnum17 for $ty {
            fn read_inline(input:&[u8])->Result<Self,ProviderError>{
                match plain_string(input)? {$($text=>Ok(Self::$variant),)+_=>Err(invalid())}
            }
        }
    };
}
inline_enum17!(PacketRestorationActivationPhase {"arm"=>Arm,"world_activate"=>WorldActivate});
inline_enum17!(PacketRestorationActivationUploadRole {"coordinator"=>Coordinator,"manifest"=>Manifest});
inline_enum17!(PacketRestoredSettledCaptureUploadOrdinal {"history_prefix"=>HistoryPrefix,"runtime_object"=>RuntimeObject});
inline_enum17!(BoundaryPolicy {"ordinary_stop"=>OrdinaryStop,"input_blocked_park"=>InputBlockedPark});
inline_enum17!(RetirementDisposition {"consumed"=>Consumed,"abandoned_inert_transfer"=>AbandonedInertTransfer});
inline_enum17!(CurrentCaptureStage17 {"receiving"=>Receiving,"raw"=>Raw,"typed"=>Typed,"failed"=>Failed});
inline_enum17!(CurrentAttemptStage17 {"receiving"=>Receiving,"raw"=>Raw,"typed"=>Typed,"authenticated"=>Authenticated,
    "dispatched"=>Dispatched,"published"=>Published,"failed"=>Failed});

pub(crate) struct ScalarRow17;
impl CurrentField17 for ScalarRow17 {
    type Native = PacketNativeStartupAllocationRow;
    fn read(
        input: &[u8],
        ledger: &mut Ledger<'_, '_, '_>,
        build: bool,
    ) -> Result<Option<Self::Native>, ProviderError> {
        ledger.read::<PacketNativeStartupAllocationRow>(input, build)
    }
    fn observe(
        value: &Self::Native,
        observer: &mut MetadataObserver<'_>,
    ) -> Result<(), ProviderError> {
        observer.observe(&value.retained_requested_bytes)?;
        observer.observe(&value.maximum_simultaneous_transient_bytes)?;
        observer.observe(&value.declared_counter_scratch_bytes)
    }
}

pub(crate) struct FixedArray32Field17;
impl CurrentField17 for FixedArray32Field17 {
    type Native = [u8; 32];
    fn read(
        input: &[u8],
        ledger: &mut Ledger<'_, '_, '_>,
        build: bool,
    ) -> Result<Option<Self::Native>, ProviderError> {
        let mut fields = Fields::array(input)?;
        let mut bytes = [0; 32];
        for byte in &mut bytes {
            let value = ledger
                .read::<u8>(fields.next()?.ok_or_else(invalid)?, true)?
                .ok_or_else(invalid)?;
            *byte = value;
        }
        fields.finish()?;
        Ok(build.then_some(bytes))
    }
    fn observe(_: &Self::Native, _: &mut MetadataObserver<'_>) -> Result<(), ProviderError> {
        Ok(())
    }
}
