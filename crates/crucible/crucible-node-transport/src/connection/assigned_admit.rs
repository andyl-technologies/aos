//! Keeps one preassigned canonical-ACK Admit in its original literal bank slot.
//!
//! Reservation precedes signing. Sealing registers only the final immutable
//! request; publication writes exactly those retained bytes. These internal
//! mechanics issue no MAC key, source admission or native ACK mechanism marker.

use super::*;
use crate::transport::original_frames::FrameDirection;

impl<S: ProviderStream> Connection<S> {
    pub(crate) fn reserve_original_assigned_ack_admit(
        &mut self,
        original: &Envelope,
        maximum: usize,
        result_slot: &mut Option<usize>,
    ) -> Result<(), ProviderError> {
        self.authenticate_native5_source_codec()?;
        if self.role != EndpointRole::Controller
            || result_slot.is_some()
            || original.message != MessageKind::Request
            || original.method != Method::Admit
            || !original.extensions.is_empty()
        {
            return Err(ProviderError::Correlation(
                "assigned Admit reservation scope",
            ));
        }
        self.validate_body(original, false)?;
        let maximum_frame = allowance(self.authority.limits().frame_bytes.get())?;
        if maximum > maximum_frame {
            return Err(ProviderError::ResourceExhausted(
                "assigned Admit frame allowance",
            ));
        }
        let id = original
            .request_id
            .0
            .as_ref()
            .ok_or(ProviderError::Correlation(
                "assigned Admit original ID absent",
            ))?;
        let bank = self
            .original_frames
            .as_ref()
            .ok_or(ProviderError::Correlation(
                "assigned Admit original bank absent",
            ))?;
        let mut bank = bank
            .try_borrow_mut()
            .map_err(|_| ProviderError::Correlation("assigned Admit original bank borrowed"))?;
        if !bank.complete() || bank.contains_original_id(id.as_str()) {
            return Err(ProviderError::Conflict(
                "assigned Admit original history changed or ID reused",
            ));
        }
        let slot = bank.begin(
            FrameDirection::Outgoing,
            maximum
                .checked_add(4)
                .ok_or(ProviderError::ResourceExhausted(
                    "assigned Admit framed extent",
                ))?,
        )?;
        *result_slot = Some(slot);
        bank.retain_request(slot, id)
    }

    pub(crate) fn seal_original_assigned_ack_admit(
        &mut self,
        original: &Envelope,
        bytes: &mut Vec<u8>,
        slot: Option<usize>,
    ) -> Result<(), ProviderError> {
        self.authenticate_native5_source_codec()?;
        self.validate_body(original, false)?;
        let maximum = bytes.capacity();
        serialized_credit(original, maximum)?;
        let value =
            serde_json::to_value(original).map_err(crucible_node_format::ContractError::from)?;
        struct RetainedWriter<'a> {
            bytes: &'a mut Vec<u8>,
            maximum: usize,
        }
        impl Write for RetainedWriter<'_> {
            fn write(&mut self, next: &[u8]) -> std::io::Result<usize> {
                if self
                    .bytes
                    .len()
                    .checked_add(next.len())
                    .is_none_or(|len| len > self.maximum)
                {
                    return Err(std::io::Error::other(
                        "assigned Admit canonical buffer credit",
                    ));
                }
                self.bytes.extend_from_slice(next);
                Ok(next.len())
            }
            fn flush(&mut self) -> std::io::Result<()> {
                Ok(())
            }
        }
        if !bytes.is_empty() {
            return Err(ProviderError::Conflict(
                "assigned Admit canonical buffer already used",
            ));
        }
        canonical::canonical_json_to_writer(&value, &mut RetainedWriter { bytes, maximum })?;
        let length = u32::try_from(bytes.len())
            .map_err(|_| ProviderError::Frame("assigned Admit header extent"))?;
        let index = slot.ok_or(ProviderError::Correlation(
            "assigned Admit original slot absent",
        ))?;
        let bank = self
            .original_frames
            .as_ref()
            .ok_or(ProviderError::Correlation(
                "assigned Admit original bank absent",
            ))?;
        let mut bank = bank
            .try_borrow_mut()
            .map_err(|_| ProviderError::Correlation("assigned Admit original bank borrowed"))?;
        let frame = bank.frames().nth(index).ok_or(ProviderError::Correlation(
            "assigned Admit original frame absent",
        ))?;
        if frame.direction != FrameDirection::Outgoing
            || !frame.bytes.is_empty()
            || frame.transferred != 0
            || frame.complete
        {
            return Err(ProviderError::Conflict(
                "assigned Admit original frame already sealed or attempted",
            ));
        }
        bank.append(index, &length.to_be_bytes())?;
        bank.append(index, bytes)?;
        drop(bank);
        self.authority
            .with_live(|| self.guard.register_outgoing(original.clone()))
    }

    pub(crate) fn publish_original_assigned_ack_admit(
        &mut self,
        original: &Envelope,
        bytes: &[u8],
        slot: Option<usize>,
    ) -> Result<(), ProviderError> {
        self.authenticate_native5_source_codec()?;
        self.check_authority()?;
        if original.message != MessageKind::Request || original.method != Method::Admit {
            return Err(ProviderError::Correlation(
                "assigned Admit publication scope",
            ));
        }
        let result = self.publish_original_send(bytes, slot);
        if result.is_err() {
            self.contain(ConnectionFailure::Write);
        }
        result
    }
}
