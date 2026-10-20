//! Borrows the complete first Controller Intent association as inert DATA.
//!
//! ```text
//! AOSXCI01 | lane[16] | operation[16] | project[16] | sandbox[16] |
//! accepted-request[32] | coissuance[32] | Controller-nonce[16] | boot[16] |
//! started:u64be | original-cutoff:u64be | J-transaction[16] | J-names[48] |
//! J-COMMIT:u64be | J-end:u64be | eleven (length:u32be, exact-field) pairs
//! fields = accepted-context, Operation, Desired, Effect, Spec-descriptor,
//!          original-coissuance, original-terminal, J-head-key, J-head,
//!          J-claim-key, J-claim
//! ```
//!
//! The accepted context is the original Effect's complete recorded public
//! mutation context, including its canonical Request. The other fields retain
//! their existing canonical owners. This framing decoder borrows every field;
//! the independent consumer must validate those nested schemas and all joins.
//! Neither a decoded Intent nor its seed supplies original custody or authority.

use sha2::{Digest as _, Sha256};

use super::super::protected_names::ProtectedJournalNamesV1;
use super::{HistoryErrorV1, nonzero, reader};

const FIXED_BYTES: usize = 264;
const FIELD_COUNT: usize = 11;
const SEED_DOMAIN: &[u8] = b"aos.sandbox.create-storage.seed.v1\0";

/// Holds fixed comparison coordinates from the actual original J append.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct ControllerIntentIdentityDataV1 {
    /// The original continuation lane.
    pub lane: [u8; 16],
    /// The accepted Create operation, distinct from Spec publication.
    pub operation: [u8; 16],
    /// The accepted Create project.
    pub project: [u8; 16],
    /// The accepted Create sandbox.
    pub sandbox: [u8; 16],
    /// The Controller scope's accepted canonical Request digest.
    pub accepted_request: [u8; 32],
    /// The original complete coissuance commitment.
    pub coissuance_binding: [u8; 32],
    /// The once-generated nonce persisted by this Intent.
    pub controller_nonce: [u8; 16],
    /// The original J clock's host boot identity.
    pub boot: [u8; 16],
    /// The original J paired BOOTTIME sample.
    pub started: u64,
    /// The unchanged accepted operation cutoff.
    pub cutoff: u64,
    /// The actual retained J transaction identity.
    pub j_transaction: [u8; 16],
    /// The actual J writer's protected physical names.
    pub j_names: ProtectedJournalNamesV1,
    /// The actual returned and read-back J COMMIT sequence.
    pub j_commit: u64,
    /// The actual returned and read-back J durable end.
    pub j_end: u64,
}

/// Borrows the exact original components of one first Controller Intent.
#[derive(Clone, Copy)]
pub struct ControllerIntentBodyDataV1<'fields> {
    /// The original fixed J and accepted-operation association.
    pub identity: ControllerIntentIdentityDataV1,
    /// The accepted recorded public mutation context, including canonical Request.
    pub accepted_context: &'fields [u8],
    /// The complete original accepted Operation row.
    pub operation: &'fields [u8],
    /// The complete original accepted Desired row.
    pub desired: &'fields [u8],
    /// The complete original accepted Effect row.
    pub effect: &'fields [u8],
    /// The existing Core canonical complete Spec descriptor.
    pub specification: &'fields [u8],
    /// The retained original coissuance's complete canonical value.
    pub coissuance: &'fields [u8],
    /// The retained original terminal's complete canonical value.
    pub terminal: &'fields [u8],
    /// The first actual J member's exact head key.
    pub j_head_key: &'fields [u8],
    /// The first actual J member's complete canonical account head.
    pub j_head: &'fields [u8],
    /// The second actual J member's exact claim key.
    pub j_claim_key: &'fields [u8],
    /// The second actual J member's complete canonical claim.
    pub j_claim: &'fields [u8],
}

impl<'fields> ControllerIntentBodyDataV1<'fields> {
    /// Borrows one exact structurally framed association without allocation.
    ///
    /// # Errors
    /// Rejects wrong magic, zero fixed identities, invalid original cutoff,
    /// malformed physical names, empty fields, truncation or trailing bytes.
    pub fn decode(bytes: &'fields [u8]) -> Result<Self, HistoryErrorV1> {
        let mut input = reader(bytes);
        if input.array::<8>()? != *b"AOSXCI01" { return Err(HistoryErrorV1::Malformed); }
        let identity = ControllerIntentIdentityDataV1 {
            lane: input.array()?, operation: input.array()?, project: input.array()?,
            sandbox: input.array()?, accepted_request: input.array()?,
            coissuance_binding: input.array()?, controller_nonce: input.array()?,
            boot: input.array()?, started: input.u64()?, cutoff: input.u64()?,
            j_transaction: input.array()?,
            j_names: ProtectedJournalNamesV1::from_bytes(input.bytes(48)?)
                .map_err(|_| HistoryErrorV1::Malformed)?,
            j_commit: input.u64()?, j_end: input.u64()?,
        };
        let mut fields = [&[][..]; FIELD_COUNT];
        for field in &mut fields {
            let length = usize::try_from(input.u32()?).map_err(|_| HistoryErrorV1::Extent)?;
            *field = input.bytes(length)?;
        }
        input.finish()?;
        let [accepted_context, operation, desired, effect, specification, coissuance,
            terminal, j_head_key, j_head, j_claim_key, j_claim] = fields;
        let value = Self { identity, accepted_context, operation, desired, effect,
            specification, coissuance, terminal, j_head_key, j_head, j_claim_key, j_claim };
        value.encoded_bytes()?;
        Ok(value)
    }

    /// Returns the checked exact encoding width from these actual borrowed fields.
    ///
    /// # Errors
    /// Rejects invalid fixed coordinates, empty fields or wire-width overflow.
    pub fn encoded_bytes(self) -> Result<usize, HistoryErrorV1> {
        let id = self.identity;
        for value in [&id.lane, &id.operation, &id.project, &id.sandbox,
            &id.controller_nonce, &id.boot, &id.j_transaction] {
            nonzero(value)?;
        }
        for value in [&id.accepted_request, &id.coissuance_binding] {
            nonzero(value)?;
        }
        ProtectedJournalNamesV1::from_bytes(&id.j_names.to_bytes())
            .map_err(|_| HistoryErrorV1::Malformed)?;
        if id.cutoff <= id.started || id.j_commit == 0 || id.j_end == 0 {
            return Err(HistoryErrorV1::Malformed);
        }
        self.fields().into_iter().try_fold(FIXED_BYTES + FIELD_COUNT * 4, |sum, field| {
            if field.is_empty() { return Err(HistoryErrorV1::Malformed); }
            u32::try_from(field.len()).map_err(|_| HistoryErrorV1::Extent)?;
            sum.checked_add(field.len()).ok_or(HistoryErrorV1::Extent)
        })
    }

    /// Writes the complete association into exactly sized caller-owned storage.
    ///
    /// # Errors
    /// Rejects malformed coordinates or a destination of a different exact width.
    pub fn encode_into(self, bytes: &mut [u8]) -> Result<(), HistoryErrorV1> {
        if bytes.len() != self.encoded_bytes()? { return Err(HistoryErrorV1::Extent); }
        let id = self.identity;
        let mut offset = 0;
        let fixed: [&[u8]; 15] = [b"AOSXCI01", &id.lane, &id.operation, &id.project,
            &id.sandbox, &id.accepted_request, &id.coissuance_binding,
            &id.controller_nonce, &id.boot, &id.started.to_be_bytes(),
            &id.cutoff.to_be_bytes(), &id.j_transaction, &id.j_names.to_bytes(),
            &id.j_commit.to_be_bytes(), &id.j_end.to_be_bytes()];
        for field in fixed {
            let end = offset + field.len();
            bytes[offset..end].copy_from_slice(field);
            offset = end;
        }
        for field in self.fields() {
            let length = u32::try_from(field.len()).map_err(|_| HistoryErrorV1::Extent)?;
            bytes[offset..offset + 4].copy_from_slice(&length.to_be_bytes());
            offset += 4;
            let end = offset + field.len();
            bytes[offset..end].copy_from_slice(field);
            offset = end;
        }
        Ok(())
    }

    fn fields(self) -> [&'fields [u8]; FIELD_COUNT] {
        [self.accepted_context, self.operation, self.desired, self.effect,
            self.specification, self.coissuance, self.terminal, self.j_head_key,
            self.j_head, self.j_claim_key, self.j_claim]
    }
}

/// Hashes the complete canonical Intent association, including actual J results.
///
/// # Errors
/// Rejects malformed structural framing. The digest grants no authority and
/// does not independently validate the borrowed nested canonical schemas.
pub fn controller_intent_seed_v1(bytes: &[u8]) -> Result<[u8; 32], HistoryErrorV1> {
    ControllerIntentBodyDataV1::decode(bytes)?;
    Ok(Sha256::new().chain_update(SEED_DOMAIN).chain_update(bytes).finalize().into())
}

#[cfg(test)]
mod tests {
    use super::*;

    // Nested fields are deliberately opaque here: their existing canonical
    // owners, not this framing codec, validate their independent semantics.
    fn data() -> ControllerIntentBodyDataV1<'static> {
        ControllerIntentBodyDataV1 {
            identity: ControllerIntentIdentityDataV1 {
                lane: [1; 16], operation: [2; 16], project: [3; 16], sandbox: [4; 16],
                accepted_request: [5; 32], coissuance_binding: [6; 32],
                controller_nonce: [7; 16], boot: [8; 16], started: 9, cutoff: 10,
                j_transaction: [11; 16], j_names: ProtectedJournalNamesV1::from_historical_fields(
                    (1, 2), (3, 4), (5, 6)), j_commit: 12, j_end: 13,
            },
            accepted_context: b"context", operation: b"operation", desired: b"desired",
            effect: b"effect", specification: b"specification", coissuance: b"coissuance",
            terminal: b"terminal", j_head_key: b"head-key", j_head: b"head",
            j_claim_key: b"claim-key", j_claim: b"claim",
        }
    }

    #[test]
    fn all_original_fields_and_actual_j_return_change_complete_intent_seed() {
        let data = data();
        let mut bytes = vec![0; data.encoded_bytes().unwrap()];
        data.encode_into(&mut bytes).unwrap();
        let original = controller_intent_seed_v1(&bytes).unwrap();
        let borrowed = ControllerIntentBodyDataV1::decode(&bytes).unwrap();

        assert_eq!(borrowed.identity, data.identity);
        assert_eq!(borrowed.accepted_context.as_ptr(), bytes[FIXED_BYTES + 4..].as_ptr());
        assert_eq!(borrowed.fields(), data.fields());

        let mut offset = FIXED_BYTES;
        for field in data.fields() {
            offset += 4;
            let mut changed = bytes.clone();
            changed[offset] ^= 1;
            assert_ne!(controller_intent_seed_v1(&changed).unwrap(), original);
            offset += field.len();
        }
        let mut changed = bytes;
        changed[255] ^= 1; // An actual J COMMIT coordinate, not a future Intent result.
        assert_ne!(controller_intent_seed_v1(&changed).unwrap(), original);
    }

    #[test]
    fn truncated_trailing_empty_and_expired_associations_stay_closed() {
        let data = data();
        let mut bytes = vec![0; data.encoded_bytes().unwrap()];
        data.encode_into(&mut bytes).unwrap();
        assert!(ControllerIntentBodyDataV1::decode(&bytes[..bytes.len() - 1]).is_err());
        let mut trailing = bytes.clone();
        trailing.push(0);
        assert!(ControllerIntentBodyDataV1::decode(&trailing).is_err());
        let mut empty = bytes.clone();
        empty[FIXED_BYTES..FIXED_BYTES + 4].copy_from_slice(&0_u32.to_be_bytes());
        assert!(ControllerIntentBodyDataV1::decode(&empty).is_err());
        bytes[176..184].copy_from_slice(&data.identity.started.to_be_bytes());
        assert!(ControllerIntentBodyDataV1::decode(&bytes).is_err());
    }
}
