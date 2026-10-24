//! Retains inert content through the same closed native storage ledger.
//!
//! The selected Observe cache can lend its original evidence independently of
//! this map. Both ordinary installation and that borrowed path use identical
//! verification and capacity checks, without a temporary evidence clone.

use super::*;

/// Retains verified bytes under the unchanged complete-content limits.
///
/// # Errors
/// Refuses a failed full reference, conflicting bytes or exhausted original
/// object/count/total byte credit.
pub(super) fn install_original_content(
    content: &mut BTreeMap<ContentRef, Vec<u8>>,
    content_bytes: &mut usize,
    complete_coordinator: bool,
    object: ContentRef,
    bytes: &[u8],
) -> Result<(), ProviderError> {
    if complete_coordinator
        && bytes.len() > super::super::coordinator::PACKET_CONNECTED_COORDINATOR_BYTES
    {
        return Err(ProviderError::ResourceExhausted(
            "packet complete connected content",
        ));
    }
    object.verify(bytes)?;
    if let Some(original) = content.get(&object) {
        return if original == bytes {
            Ok(())
        } else {
            Err(ProviderError::Conflict("packet original content"))
        };
    }
    let total = (*content_bytes)
        .checked_add(bytes.len())
        .ok_or(ProviderError::ResourceExhausted("packet content bytes"))?;
    // Only explicitly installed connected-four/complete-five coordinators need the larger
    // complete coordinator object. Socket frames and old profiles stay fixed;
    // every byte remains charged to the same original total content ledger.
    let maximum_object = if complete_coordinator {
        super::super::coordinator::PACKET_CONNECTED_COORDINATOR_BYTES
    } else {
        FRAME
    };
    if content.len() >= OBJECTS || total > CONTENT_BYTES || bytes.len() > maximum_object {
        return Err(ProviderError::ResourceExhausted(
            "packet complete native content",
        ));
    }
    content.insert(object, bytes.to_vec());
    *content_bytes = total;
    Ok(())
}
