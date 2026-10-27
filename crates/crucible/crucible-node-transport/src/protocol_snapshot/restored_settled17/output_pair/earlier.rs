//! Binds the earlier completed Capture and its retained native output banks.

use super::*;
use crate::protocol_snapshot::compact_bytes::ValidatedCompactBytes;

/// Borrows the original SDK Capture and the exact retained native output views.
///
/// The enclosing comparison authenticates both complete current graphs before
/// assembling this inert input. Every earlier occurrence and bank check remains
/// necessary; this view supplies no completion, registration or Capture right.
pub(super) struct EarlierCapture17InputsData<'loan, 'plan> {
    /// Selects the same earlier occurrence in the after graph's chronology.
    pub(super) index: usize,
    /// Borrows the actual independently verified signed Capture artifact.
    pub(super) artifact: &'loan PacketRestoredSettledCaptureArtifact,
    /// Borrows the same Source-selected Capture context.
    pub(super) context: &'loan PacketRestoredSettledCaptureContext,
    /// Borrows its registered original request.
    pub(super) original: &'loan Envelope,
    /// Borrows the original Capture arguments.
    pub(super) arguments: &'loan CaptureArguments,
    /// Borrows that occurrence's baseline Begin body.
    pub(super) begin: &'loan BeginRequest,
    /// Borrows its completed SDK terminal.
    pub(super) terminal: &'loan Envelope,
    /// Borrows the current confirmation's exact output references.
    pub(super) confirmation: &'loan PacketRestoredSettledAfterConfirmationRequest,
    /// Borrows the independently checked complete snapshot plan.
    pub(super) snapshot: &'loan PacketNativeRestoredSettled17SnapshotPlan<'plan>,
    /// Borrows the same independently authenticated anchor bytes.
    pub(super) anchor_raw: &'loan [u8],
    /// Borrows the exact complete before graph bytes.
    pub(super) before_body: &'loan [u8],
}

/// Authenticates the exact earlier occurrence and all retained Capture outputs.
///
/// # Errors
/// Refuses changed chronology, signed inputs, registration, cached terminal,
/// output references, complete bank bytes or original snapshot correspondence.
pub(super) fn authenticate(
    after: &NativeCurrentGraph17Data,
    inputs: EarlierCapture17InputsData<'_, '_>,
) -> Result<(), ProviderError> {
    let EarlierCapture17InputsData {
        index,
        artifact,
        context,
        original,
        arguments,
        begin,
        terminal,
        confirmation,
        snapshot,
        anchor_raw,
        before_body,
    } = inputs;

    let roots = after.raw_root_spans_data()?;
    let wrapper = action(roots.boot_data(), index)?;
    if unsigned(field(wrapper, "ordinal")?)?
        != u64::try_from(index)
            .map_err(|_| invalid())?
            .checked_add(1)
            .ok_or_else(invalid)?
        || field(wrapper, "decoded")? != b"true"
        || field(wrapper, "failed")? != b"false"
    {
        return Err(invalid());
    }

    emitted(field(wrapper, "original")?, original)?;
    let selected = field(wrapper, "selected")?;
    if plain_string(field(selected, "family")?)? != "capture" {
        return Err(invalid());
    }
    let capture = field(selected, "data")?;
    if plain_string(field(field(capture, "body")?, "kind")?)? != "capture"
        || plain_string(field(capture, "stage")?)? != "typed"
        || field(capture, "confirmation")? != b"null"
        || field(capture, "confirmation_receipt")? != b"null"
    {
        return Err(invalid());
    }

    emitted(field(capture, "original")?, original)?;
    emitted(field(capture, "arguments")?, arguments)?;
    emitted(field(capture, "capture")?, artifact)?;
    emitted(field(capture, "capture_context")?, context)?;
    emitted(field(capture, "terminal")?, terminal)?;
    emitted(field(capture, "prepared_reply")?, &terminal.body)?;
    let registration = field(capture, "registration")?;
    if plain_string(field(registration, "capture_identity_role")?)?
        != "current-native-control-identity"
        || unsigned(field(registration, "creator")?)? != u64::from(after.creator_data())
    {
        return Err(invalid());
    }

    // The full root grammar defines one Control identity before any registration;
    // every such role consumed its actual Shared row and that exact root alias.
    emitted(field(registration, "request")?, original)?;
    emitted(field(registration, "arguments")?, arguments)?;
    emitted(field(registration, "begin")?, begin)?;

    let output = field(capture, "outputs")?;
    if plain_string(field(output, "schema")?)?
        != "source-private.native-capture-retained-outputs/17"
        || field(output, "reserved")? != b"true"
        || field(output, "failed")? != b"false"
    {
        return Err(invalid());
    }

    let mut banks = Fields::array(field(output, "banks")?)?;
    bank(
        banks.next_value()?.ok_or_else(invalid)?,
        &confirmation.native_snapshot_ref,
        None,
    )?;
    bank(
        banks.next_value()?.ok_or_else(invalid)?,
        &confirmation.native_control_ref,
        Some(snapshot.control_bytes()),
    )?;
    let before_bank = banks.next_value()?.ok_or_else(invalid)?;
    before(before_bank, snapshot, before_body)?;
    bank(
        banks.next_value()?.ok_or_else(invalid)?,
        &confirmation.native_anchor_ref,
        Some(anchor_raw),
    )?;
    let _ = banks.next_value()?.ok_or_else(invalid)?;
    banks.finish()
}

fn bank(input: &[u8], expected: &ContentRef, body: Option<&[u8]>) -> Result<(), ProviderError> {
    let mut f = Fields::object(input)?;
    let plan = compact(f.named("bytes")?)?;
    emitted(f.named("reference")?, expected)?;
    if f.named("attempted")? != b"true" {
        return Err(invalid());
    }
    f.finish()?;
    expected.validate()?;
    if expected.media_type != "application/json"
        || expected.hash.algorithm != "blake3-256"
        || expected.hash.domain != "cnp.blob.v1"
        || u64::try_from(plan.decoded_length()).map_err(|_| invalid())? != expected.length.get()
    {
        return Err(invalid());
    }

    let mut hash = blake3::Hasher::new();
    hash.update(b"CNP/1\0");
    hash.update(&11u32.to_be_bytes());
    hash.update(b"cnp.blob.v1");
    hash.update(&expected.length.get().to_be_bytes());
    visit(&plan, body, &mut hash)?;
    if hash.finalize().to_hex().as_str() != expected.hash.digest {
        return Err(invalid());
    }
    Ok(())
}

fn before(
    input: &[u8],
    snapshot: &PacketNativeRestoredSettled17SnapshotPlan<'_>,
    before_body: &[u8],
) -> Result<(), ProviderError> {
    let mut f = Fields::object(input)?;
    let plan = compact(f.named("bytes")?)?;
    if reference(f.named("reference")?)? != reference(snapshot.before().reference_bytes())?
        || f.named("attempted")? != b"true"
    {
        return Err(invalid());
    }
    f.finish()?;
    // The outer plan has already authenticated the compact bytes and fullref.
    // Compare every retained bank byte with that same exact before body.
    if plan.decoded_length() != snapshot.before().encoded_length() {
        return Err(invalid());
    }
    // Its reference authenticates bytes independently; stream the retained bank
    // under the same normative content framing rather than allocating a copy.
    let expected = reference(snapshot.before().reference_bytes())?;
    let mut hash = blake3::Hasher::new();
    hash.update(b"CNP/1\0");
    hash.update(&11u32.to_be_bytes());
    hash.update(b"cnp.blob.v1");
    hash.update(&expected.length.to_be_bytes());
    visit(&plan, Some(before_body), &mut hash)?;
    if hash.finalize().to_hex().as_str() != expected.digest {
        return Err(invalid());
    }
    Ok(())
}

fn compact(input: &[u8]) -> Result<ValidatedCompactBytes<'_>, ProviderError> {
    let mut f = Fields::array(input)?;
    let raw = f.next_value()?.ok_or_else(invalid)?;
    let capacity =
        usize::try_from(unsigned(f.next_value()?.ok_or_else(invalid)?)?).map_err(|_| invalid())?;
    f.finish()?;
    ValidatedCompactBytes::validate(raw, raw.len(), capacity)
}

fn visit(
    plan: &ValidatedCompactBytes<'_>,
    body: Option<&[u8]>,
    hash: &mut blake3::Hasher,
) -> Result<(), ProviderError> {
    if body.is_some_and(|body| body.len() != plan.decoded_length()) {
        return Err(invalid());
    }
    let mut offset = 0usize;
    let mut scratch = [0u8; 1024];
    while offset < plan.decoded_length() {
        let length = (plan.decoded_length() - offset).min(scratch.len());
        plan.copy_range(offset, &mut scratch[..length])?;
        if body.is_some_and(|body| body.get(offset..offset + length) != Some(&scratch[..length])) {
            return Err(invalid());
        }
        hash.update(&scratch[..length]);
        offset = offset.checked_add(length).ok_or_else(invalid)?;
    }
    Ok(())
}

#[derive(Eq, PartialEq)]
struct Reference<'a> {
    algorithm: &'a str,
    digest: &'a str,
    domain: &'a str,
    length: u64,
    media: &'a str,
}

fn reference(input: &[u8]) -> Result<Reference<'_>, ProviderError> {
    let hash = field(input, "hash")?;
    let result = Reference {
        algorithm: plain_string(field(hash, "algorithm")?)?,
        digest: plain_string(field(hash, "digest")?)?,
        domain: plain_string(field(hash, "domain")?)?,
        length: unsigned(plain_string(field(input, "length")?)?.as_bytes())?,
        media: plain_string(field(input, "media_type")?)?,
    };
    if result.algorithm != "blake3-256"
        || result.domain != "cnp.blob.v1"
        || result.media != "application/json"
        || result.digest.len() != 64
    {
        return Err(invalid());
    }
    Ok(result)
}
