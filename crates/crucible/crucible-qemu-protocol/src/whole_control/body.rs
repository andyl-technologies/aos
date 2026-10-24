//! Complete immutable whole-operation request, result, and ACK bodies.
//!
//! Encoders write into caller-owned backing. Decoders borrow that same backing;
//! no protocol operation allocates or replaces a retained historical body.
//! Hashes correlate complete bytes. They do not establish native eligibility,
//! current source ownership, input completeness, or a stopped-cut receipt.
//!
//! ```text
//! request: version:u32, extent:u32, scope[32], epoch:u64, sequence:u64,
//!          commitments[96], start[24], limit[24], quotas[48], inventory_extent:u32,
//!          reserved:u32, inventory[N] (fixed header = 256 bytes)
//! result:  fixed header = 336 bytes, followed by the complete output inventory
//! ACK:     version:u32, extent:u32, scope[32], epoch:u64, sequence:u64,
//!          cut:u64, request_digest[32], result_digest[32] (128 bytes)
//! all integers are big-endian; each extent counts the complete body
//! ```

use super::{
    WHOLE_ACK_BYTES, WHOLE_BODY_MAX_BYTES, WHOLE_REQUEST_HEADER_BYTES, WHOLE_RESULT_HEADER_BYTES,
    WholeControlError, domain_digest, put_u32, put_u64, read_u32, read_u64,
};

const REQUEST_DOMAIN: &[u8] = b"crucible.qemu.whole.request.v1\0";
const RESULT_DOMAIN: &[u8] = b"crucible.qemu.whole.result.v1\0";
const INPUT_DOMAIN: &[u8] = b"crucible.qemu.whole.input-inventory.v1\0";
const OUTPUT_DOMAIN: &[u8] = b"crucible.qemu.whole.output-inventory.v1\0";

/// Retains the independently charged source allowances of one operation.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct WholeOperationQuota {
    /// Bounds actual input payload bytes.
    pub input_bytes: u64,
    /// Bounds actual input records.
    pub input_records: u64,
    /// Bounds actual output payload bytes.
    pub output_bytes: u64,
    /// Bounds actual output records.
    pub output_records: u64,
    /// Bounds genuine CPU retirements.
    pub cpu_retirements: u64,
    /// Bounds timer, worker, and synchronous event steps.
    pub event_steps: u64,
}

/// Borrows one complete original whole-operation request inventory.
///
/// Position encoding deliberately selects BoundaryControl, round zero, on the
/// 50 ps grid. Another common Position must use a separately qualified edition.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct WholeRequest<'a> {
    /// Binds the constructor-selected immutable protocol scope.
    pub scope: [u8; 32],
    /// Correlates the original source-issued world epoch.
    pub epoch: u64,
    /// Names the never-recycled operation slot, starting at one.
    pub sequence: u64,
    /// Commits the complete original common grant data.
    pub grant_digest: [u8; 32],
    /// Commits the source-selected binding and realization data.
    pub binding_digest: [u8; 32],
    /// Names the authentic original stopped physical coordinate.
    pub start_ps: u64,
    /// Names the half-open admitted physical ceiling.
    pub limit_ps: u64,
    /// Retains all original independently charged quotas.
    pub quota: WholeOperationQuota,
    /// Borrows the complete portable input and payload envelope.
    pub input_inventory: &'a [u8],
}

impl<'a> WholeRequest<'a> {
    /// Decodes a complete request before any payload effects.
    ///
    /// # Errors
    /// Rejects unsupported positions, malformed extent or reserved fields,
    /// absent correlations, non-grid limits, or an inventory digest mismatch.
    pub fn decode(body: &'a [u8]) -> Result<Self, WholeControlError> {
        Self::decode_input(body, false)
    }

    /// Decodes a request whose input is committed edition-two stage references.
    ///
    /// # Errors
    /// Rejects malformed request or reference bytes. Original committed stage
    /// ownership, record ranges and native currentness require source validation.
    pub fn decode_staged(body: &'a [u8]) -> Result<Self, WholeControlError> {
        Self::decode_input(body, true)
    }

    fn decode_input(body: &'a [u8], staged: bool) -> Result<Self, WholeControlError> {
        check_body(body, WHOLE_REQUEST_HEADER_BYTES)?;
        if read_u32(body, 248) as usize != body.len() - WHOLE_REQUEST_HEADER_BYTES
            || read_u32(body, 252) != 0
            || [160, 168, 184, 192]
                .into_iter()
                .any(|offset| read_u64(body, offset) != 0)
        {
            return Err(WholeControlError::Body);
        }
        let request = Self {
            scope: array32(body, 8),
            epoch: read_u64(body, 40),
            sequence: read_u64(body, 48),
            grant_digest: array32(body, 56),
            binding_digest: array32(body, 88),
            start_ps: read_u64(body, 152),
            limit_ps: read_u64(body, 176),
            quota: WholeOperationQuota {
                input_bytes: read_u64(body, 200),
                input_records: read_u64(body, 208),
                output_bytes: read_u64(body, 216),
                output_records: read_u64(body, 224),
                cpu_retirements: read_u64(body, 232),
                event_steps: read_u64(body, 240),
            },
            input_inventory: &body[WHOLE_REQUEST_HEADER_BYTES..],
        };
        request.validate_input(staged)?;
        if array32(body, 120) != domain_digest(INPUT_DOMAIN, request.input_inventory) {
            return Err(WholeControlError::Correlation);
        }
        Ok(request)
    }

    /// Writes the complete request into preowned exact-size backing.
    ///
    /// # Errors
    /// Rejects invalid request data or backing with another extent.
    pub fn encode_into(&self, body: &mut [u8]) -> Result<(), WholeControlError> {
        self.encode_input(body, false)
    }

    /// Encodes a compute request referencing the same committed staged inputs.
    ///
    /// # Errors
    /// Rejects malformed requests, stage references or incorrectly sized backing.
    /// Encoding supplies no native stage authority or permission for effects.
    pub fn encode_staged_into(&self, body: &mut [u8]) -> Result<(), WholeControlError> {
        self.encode_input(body, true)
    }

    fn encode_input(&self, body: &mut [u8], staged: bool) -> Result<(), WholeControlError> {
        self.validate_input(staged)?;
        check_destination(body, WHOLE_REQUEST_HEADER_BYTES, self.input_inventory.len())?;
        body.fill(0);
        put_u32(body, 0, 1);
        put_u32(body, 4, body.len() as u32);
        body[8..40].copy_from_slice(&self.scope);
        put_u64(body, 40, self.epoch);
        put_u64(body, 48, self.sequence);
        body[56..88].copy_from_slice(&self.grant_digest);
        body[88..120].copy_from_slice(&self.binding_digest);
        body[120..152].copy_from_slice(&domain_digest(INPUT_DOMAIN, self.input_inventory));
        put_u64(body, 152, self.start_ps);
        put_u64(body, 176, self.limit_ps);
        let quota = [
            self.quota.input_bytes,
            self.quota.input_records,
            self.quota.output_bytes,
            self.quota.output_records,
            self.quota.cpu_retirements,
            self.quota.event_steps,
        ];
        for (index, value) in quota.into_iter().enumerate() {
            put_u64(body, 200 + index * 8, value);
        }
        put_u32(body, 248, self.input_inventory.len() as u32);
        body[WHOLE_REQUEST_HEADER_BYTES..].copy_from_slice(self.input_inventory);
        Ok(())
    }

    fn validate_input(&self, staged: bool) -> Result<(), WholeControlError> {
        if self.scope == [0; 32]
            || self.epoch == 0
            || self.sequence == 0
            || self.grant_digest == [0; 32]
            || self.binding_digest == [0; 32]
            || self.limit_ps <= self.start_ps
            || self.limit_ps > i64::MAX as u64
            || !self.start_ps.is_multiple_of(50)
            || !self.limit_ps.is_multiple_of(50)
            || self.quota.cpu_retirements == 0
            || self.quota.event_steps == 0
            || self.input_inventory.is_empty()
            || (!staged && self.quota.input_records > self.input_inventory.len() as u64)
            || self.input_inventory.len()
                > WHOLE_BODY_MAX_BYTES as usize - WHOLE_REQUEST_HEADER_BYTES
        {
            return Err(WholeControlError::Body);
        }
        if staged {
            super::staged::body::StageReferences::decode(self.input_inventory)?;
        }
        Ok(())
    }
}

/// Classifies an authentic native result without upgrading uncertain progress.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
#[repr(u32)]
pub enum WholeResultDisposition {
    /// The source reports the complete admitted operation.
    Complete = 1,
    /// The source retains an unresolved original operation.
    Unknown = 3,
}

/// Borrows the complete original native result and output inventory.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct WholeResult<'a> {
    /// Binds the constructor-selected immutable protocol scope.
    pub scope: [u8; 32],
    /// Correlates the original source-issued world epoch.
    pub epoch: u64,
    /// Names the original never-recycled operation slot.
    pub sequence: u64,
    /// Commits the entire original request body.
    pub request_digest: [u8; 32],
    /// Retains the request's original source binding digest.
    pub binding_digest: [u8; 32],
    /// Retains the request's complete input inventory digest.
    pub input_inventory_digest: [u8; 32],
    /// Records the actual native stopped physical coordinate.
    pub stopped_ps: u64,
    /// Retains the original admitted physical ceiling.
    pub limit_ps: u64,
    /// Records the authentic original raw retirement frontier.
    pub raw_before: u64,
    /// Records the authentic resulting raw retirement frontier.
    pub raw_after: u64,
    /// Counts independently observed CPU retirements.
    pub retired: u64,
    /// Counts authentic service callbacks, independently of event steps.
    pub callbacks: u64,
    /// Counts actual accepted input records.
    pub input_records: u64,
    /// Counts actual accepted input bytes.
    pub input_bytes: u64,
    /// Counts actual published output records.
    pub output_records: u64,
    /// Counts actual published output bytes.
    pub output_bytes: u64,
    /// Names the source-issued original resulting stopped cut.
    pub cut: u64,
    /// Preserves complete versus uncertain native custody.
    pub disposition: WholeResultDisposition,
    /// Counts independently charged actual event steps.
    pub event_steps: u64,
    /// Retains the original request's event allowance.
    pub event_allowance: u64,
    /// Borrows the entire immutable output envelope.
    pub output_inventory: &'a [u8],
}

impl<'a> WholeResult<'a> {
    /// Decodes one complete result while retaining Unknown as Unknown.
    ///
    /// # Errors
    /// Rejects malformed extents, unsupported phase, reserved bytes, counters,
    /// or an output digest mismatch. This does not authenticate stopped state.
    pub fn decode(body: &'a [u8]) -> Result<Self, WholeControlError> {
        check_body(body, WHOLE_RESULT_HEADER_BYTES)?;
        let disposition = match read_u32(body, 304) {
            1 => WholeResultDisposition::Complete,
            3 => WholeResultDisposition::Unknown,
            _ => return Err(WholeControlError::Body),
        };
        if read_u32(body, 308) as usize != body.len() - WHOLE_RESULT_HEADER_BYTES
            || body[312..320] != [0; 8]
            || [160, 168, 184, 192]
                .into_iter()
                .any(|offset| read_u64(body, offset) != 0)
        {
            return Err(WholeControlError::Body);
        }
        let result = Self {
            scope: array32(body, 8),
            epoch: read_u64(body, 40),
            sequence: read_u64(body, 48),
            request_digest: array32(body, 56),
            binding_digest: array32(body, 88),
            input_inventory_digest: array32(body, 120),
            stopped_ps: read_u64(body, 152),
            limit_ps: read_u64(body, 176),
            raw_before: read_u64(body, 200),
            raw_after: read_u64(body, 208),
            retired: read_u64(body, 216),
            callbacks: read_u64(body, 224),
            input_records: read_u64(body, 232),
            input_bytes: read_u64(body, 240),
            output_records: read_u64(body, 248),
            output_bytes: read_u64(body, 256),
            cut: read_u64(body, 296),
            disposition,
            event_steps: read_u64(body, 320),
            event_allowance: read_u64(body, 328),
            output_inventory: &body[WHOLE_RESULT_HEADER_BYTES..],
        };
        result.validate()?;
        if array32(body, 264) != domain_digest(OUTPUT_DOMAIN, result.output_inventory) {
            return Err(WholeControlError::Correlation);
        }
        Ok(result)
    }

    /// Writes the immutable result into exact-size preowned backing.
    ///
    /// # Errors
    /// Rejects malformed result data or a destination with another extent.
    pub fn encode_into(&self, body: &mut [u8]) -> Result<(), WholeControlError> {
        self.validate()?;
        check_destination(body, WHOLE_RESULT_HEADER_BYTES, self.output_inventory.len())?;
        body.fill(0);
        put_u32(body, 0, 1);
        put_u32(body, 4, body.len() as u32);
        body[8..40].copy_from_slice(&self.scope);
        put_u64(body, 40, self.epoch);
        put_u64(body, 48, self.sequence);
        body[56..88].copy_from_slice(&self.request_digest);
        body[88..120].copy_from_slice(&self.binding_digest);
        body[120..152].copy_from_slice(&self.input_inventory_digest);
        let observations = [
            (152, self.stopped_ps),
            (176, self.limit_ps),
            (200, self.raw_before),
            (208, self.raw_after),
            (216, self.retired),
            (224, self.callbacks),
            (232, self.input_records),
            (240, self.input_bytes),
            (248, self.output_records),
            (256, self.output_bytes),
            (296, self.cut),
            (320, self.event_steps),
            (328, self.event_allowance),
        ];
        for (offset, value) in observations {
            put_u64(body, offset, value);
        }
        body[264..296].copy_from_slice(&domain_digest(OUTPUT_DOMAIN, self.output_inventory));
        put_u32(body, 304, self.disposition as u32);
        put_u32(body, 308, self.output_inventory.len() as u32);
        body[WHOLE_RESULT_HEADER_BYTES..].copy_from_slice(self.output_inventory);
        Ok(())
    }

    /// Correlates this result to the exact complete retained original request.
    ///
    /// # Errors
    /// Rejects any changed commitment, coordinate, or allowance. Complete also
    /// requires the original ceiling and all original actual-count bounds.
    /// Unknown remains unacknowledgeable even when its counts happen to be zero.
    pub fn validate_against(&self, request_body: &[u8]) -> Result<(), WholeControlError> {
        let request = WholeRequest::decode(request_body)?;
        self.validate_request(request_body, &request)
    }

    /// Correlates the complete result to its original staged compute request.
    ///
    /// # Errors
    /// Rejects malformed references or any changed request/result correlation.
    /// Native source validation separately resolves the original committed stages.
    pub fn validate_against_staged(&self, request_body: &[u8]) -> Result<(), WholeControlError> {
        let request = WholeRequest::decode_staged(request_body)?;
        self.validate_request(request_body, &request)
    }

    fn validate_request(
        &self,
        request_body: &[u8],
        request: &WholeRequest<'_>,
    ) -> Result<(), WholeControlError> {
        self.validate()?;
        if self.scope != request.scope
            || self.epoch != request.epoch
            || self.sequence != request.sequence
            || self.binding_digest != request.binding_digest
            || self.request_digest != domain_digest(REQUEST_DOMAIN, request_body)
            || self.input_inventory_digest != domain_digest(INPUT_DOMAIN, request.input_inventory)
            || self.limit_ps != request.limit_ps
            || self.stopped_ps < request.start_ps
            || self.stopped_ps > request.limit_ps
            || self.event_allowance != request.quota.event_steps
        {
            return Err(WholeControlError::Correlation);
        }
        if self.disposition == WholeResultDisposition::Complete
            && (self.stopped_ps != request.limit_ps
                || self.retired > request.quota.cpu_retirements
                || self.event_steps > request.quota.event_steps
                || self.input_bytes > request.quota.input_bytes
                || self.input_records > request.quota.input_records
                || self.output_bytes > request.quota.output_bytes
                || self.output_records > request.quota.output_records)
        {
            return Err(WholeControlError::Correlation);
        }
        Ok(())
    }

    fn validate(&self) -> Result<(), WholeControlError> {
        if self.scope == [0; 32]
            || self.epoch == 0
            || self.sequence == 0
            || self.cut == 0
            || self.request_digest == [0; 32]
            || self.binding_digest == [0; 32]
            || self.input_inventory_digest == [0; 32]
            || self.raw_after < self.raw_before
            || self.retired != self.raw_after - self.raw_before
            || self.callbacks > self.event_steps
            || self.stopped_ps > self.limit_ps
            || (self.disposition == WholeResultDisposition::Complete
                && self.stopped_ps != self.limit_ps)
            || self.stopped_ps > i64::MAX as u64
            || self.limit_ps > i64::MAX as u64
            || self.output_inventory.is_empty()
            || self.output_inventory.len()
                > WHOLE_BODY_MAX_BYTES as usize - WHOLE_RESULT_HEADER_BYTES
        {
            return Err(WholeControlError::Body);
        }
        Ok(())
    }
}

/// Retains the complete request and result correlation of one source ACK.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct WholeAcknowledgement {
    /// Binds the constructor-selected immutable scope.
    pub scope: [u8; 32],
    /// Correlates the source-issued fixed world epoch.
    pub epoch: u64,
    /// Names the original operation slot.
    pub sequence: u64,
    /// Names the authentic stopped cut from the complete result.
    pub cut: u64,
    /// Commits the complete original request body.
    pub request_digest: [u8; 32],
    /// Commits the complete original result, including all output bytes.
    pub result_digest: [u8; 32],
}

impl WholeAcknowledgement {
    /// Constructs an ACK only for an exactly correlated Complete result.
    ///
    /// # Errors
    /// Rejects changed request/result data or any authentic Unknown result.
    /// Construction offers no bytes and does not assert native consumption.
    pub fn for_complete(request: &[u8], result: &[u8]) -> Result<Self, WholeControlError> {
        Self::for_complete_input(request, result, false)
    }

    /// Constructs an ACK for an exactly correlated complete staged compute result.
    ///
    /// # Errors
    /// Rejects malformed stage references, changed correlations or Unknown
    /// results. The constructed bytes do not assert native ACK consumption.
    pub fn for_complete_staged(request: &[u8], result: &[u8]) -> Result<Self, WholeControlError> {
        Self::for_complete_input(request, result, true)
    }

    fn for_complete_input(
        request: &[u8],
        result: &[u8],
        staged: bool,
    ) -> Result<Self, WholeControlError> {
        let decoded = WholeResult::decode(result)?;
        if staged {
            decoded.validate_against_staged(request)?;
        } else {
            decoded.validate_against(request)?;
        }
        if decoded.disposition != WholeResultDisposition::Complete {
            return Err(WholeControlError::Unknown);
        }
        Ok(Self {
            scope: decoded.scope,
            epoch: decoded.epoch,
            sequence: decoded.sequence,
            cut: decoded.cut,
            request_digest: domain_digest(REQUEST_DOMAIN, request),
            result_digest: domain_digest(RESULT_DOMAIN, result),
        })
    }

    /// Decodes one exact closed ACK body.
    ///
    /// # Errors
    /// Rejects wrong extent, edition, or absent original correlations.
    pub fn decode(body: &[u8]) -> Result<Self, WholeControlError> {
        if body.len() != WHOLE_ACK_BYTES
            || read_u32(body, 0) != 1
            || read_u32(body, 4) as usize != WHOLE_ACK_BYTES
        {
            return Err(WholeControlError::Body);
        }
        let ack = Self {
            scope: array32(body, 8),
            epoch: read_u64(body, 40),
            sequence: read_u64(body, 48),
            cut: read_u64(body, 56),
            request_digest: array32(body, 64),
            result_digest: array32(body, 96),
        };
        ack.validate()?;
        Ok(ack)
    }

    /// Encodes the complete closed acknowledgement without native layout reuse.
    ///
    /// # Errors
    /// Rejects absent correlations before encoding the body.
    pub fn encode(&self) -> Result<[u8; WHOLE_ACK_BYTES], WholeControlError> {
        self.validate()?;
        let mut body = [0; WHOLE_ACK_BYTES];
        put_u32(&mut body, 0, 1);
        put_u32(&mut body, 4, WHOLE_ACK_BYTES as u32);
        body[8..40].copy_from_slice(&self.scope);
        put_u64(&mut body, 40, self.epoch);
        put_u64(&mut body, 48, self.sequence);
        put_u64(&mut body, 56, self.cut);
        body[64..96].copy_from_slice(&self.request_digest);
        body[96..128].copy_from_slice(&self.result_digest);
        Ok(body)
    }

    /// Checks the ACK against both complete immutable historical bodies.
    ///
    /// # Errors
    /// Rejects a changed correlation or any Unknown result.
    pub fn validate_against(&self, request: &[u8], result: &[u8]) -> Result<(), WholeControlError> {
        if self != &Self::for_complete(request, result)? {
            return Err(WholeControlError::Correlation);
        }
        Ok(())
    }

    /// Checks the complete ACK against its original staged request and result.
    ///
    /// # Errors
    /// Rejects malformed stage references, changed correlations or Unknown results.
    pub fn validate_against_staged(
        &self,
        request: &[u8],
        result: &[u8],
    ) -> Result<(), WholeControlError> {
        if self != &Self::for_complete_staged(request, result)? {
            return Err(WholeControlError::Correlation);
        }
        Ok(())
    }

    fn validate(&self) -> Result<(), WholeControlError> {
        if self.scope == [0; 32]
            || self.epoch == 0
            || self.sequence == 0
            || self.cut == 0
            || self.request_digest == [0; 32]
            || self.result_digest == [0; 32]
        {
            return Err(WholeControlError::Body);
        }
        Ok(())
    }
}

/// Commits an already validated complete original request body.
///
/// # Errors
/// Rejects malformed request bytes before deriving their correlation.
pub fn whole_request_digest(body: &[u8]) -> Result<[u8; 32], WholeControlError> {
    WholeRequest::decode(body)?;
    Ok(domain_digest(REQUEST_DOMAIN, body))
}

/// Commits a complete validated staged compute request and all its references.
///
/// # Errors
/// Rejects malformed request or staged reference bytes before hashing.
pub fn whole_staged_request_digest(body: &[u8]) -> Result<[u8; 32], WholeControlError> {
    WholeRequest::decode_staged(body)?;
    Ok(domain_digest(REQUEST_DOMAIN, body))
}

fn array32(body: &[u8], offset: usize) -> [u8; 32] {
    let mut result = [0; 32];
    result.copy_from_slice(&body[offset..offset + 32]);
    result
}

fn check_body(body: &[u8], header: usize) -> Result<(), WholeControlError> {
    if body.len() <= header
        || body.len() > WHOLE_BODY_MAX_BYTES as usize
        || read_u32(body, 0) != 1
        || read_u32(body, 4) as usize != body.len()
    {
        return Err(WholeControlError::Body);
    }
    Ok(())
}

fn check_destination(
    body: &[u8],
    header: usize,
    inventory: usize,
) -> Result<(), WholeControlError> {
    if inventory == 0
        || header.checked_add(inventory) != Some(body.len())
        || body.len() > WHOLE_BODY_MAX_BYTES as usize
    {
        return Err(WholeControlError::Body);
    }
    Ok(())
}
