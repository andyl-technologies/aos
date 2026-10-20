//! Checks native token/identity framing and exact retained literal commitments.
//!
//! These borrowed plans are only historical DATA. The enclosing complete17
//! reader must validate actual Authority/frames/Boot/Prepare/Commit role bodies
//! and all their same-role joins. No plan constructs any native token or claim.

use super::*;
use crate::protocol_snapshot::owned11::typed::{Fields, plain_string, unsigned};

#[derive(Clone, Copy, Eq, PartialEq)]
pub(crate) enum NativeToken17Kind {
    Ack,
    Prepare,
    Commit,
}

pub(crate) struct NativeIdentity17Plan<'a> {
    pub(crate) authority: &'a [u8],
    pub(crate) request_id: &'a [u8],
    pub(crate) sequence: u64,
    pub(crate) literal_slot: usize,
    literal_length: usize,
    literal_digest: [u8; 32],
}

impl<'a> NativeIdentity17Plan<'a> {
    fn validate(input: &'a [u8], ack: bool) -> Result<Self, ProviderError> {
        let mut fields = Fields::object(input)?;
        exact_text(fields.named("actor_role")?, "native-connection-actor")?;
        let (request_id, sequence) = if ack {
            let request = fields.named("admit_id")?;
            let sequence = quoted_u64(fields.named("admit_sequence")?)?;
            (request, sequence)
        } else {
            // Canonical non-ACK identities put authority before request_id.
            (&b""[..], 0)
        };
        let authority = fields.named("authority")?;
        exact_text(fields.named("frames_role")?, "native-connection-frames")?;
        let mut digest = Fields::array(fields.named("literal_digest")?)?;
        let mut literal_digest = [0u8; 32];
        for byte in &mut literal_digest {
            *byte = u8::try_from(unsigned(digest.next()?.ok_or_else(invalid)?)?)
                .map_err(|_| invalid())?;
        }
        digest.finish()?;
        let (literal_slot, literal_length) = if ack {
            let slot = quantity(fields.named("literal_index")?)?;
            (slot, quantity(fields.named("literal_length")?)?)
        } else {
            let length = quantity(fields.named("literal_length")?)?;
            (quantity(fields.named("literal_slot")?)?, length)
        };
        exact_text(fields.named("policy_role")?, "native-policy")?;
        let request_id = if ack {
            request_id
        } else {
            fields.named("request_id")?
        };
        let id = plain_string(request_id)?;
        if id.is_empty() || id.len() > 128 || !id.is_ascii() || literal_length < 4 {
            return Err(invalid());
        }
        exact_text(
            fields.named("schema")?,
            if ack {
                "source-private.native-ack-connection-identity-history/17"
            } else {
                "source-private.native-restoration-connection-identity-history/17"
            },
        )?;
        let sequence = if ack {
            sequence
        } else {
            quoted_u64(fields.named("sequence")?)?
        };
        fields.finish()?;
        Ok(Self {
            authority,
            request_id,
            sequence,
            literal_slot,
            literal_length,
            literal_digest,
        })
    }

    /// Checks the complete framed literal, including its original length prefix.
    pub(crate) fn authenticate_literal_data(&self, frame: &[u8]) -> Result<(), ProviderError> {
        let prefix: [u8; 4] = frame
            .get(..4)
            .ok_or_else(invalid)?
            .try_into()
            .map_err(|_| invalid())?;
        if frame.len() != self.literal_length
            || usize::try_from(u32::from_be_bytes(prefix)).map_err(|_| invalid())?
                != frame.len() - 4
            || blake3::hash(frame).as_bytes() != &self.literal_digest
        {
            return Err(invalid());
        }
        Ok(())
    }
}

pub(crate) struct NativeToken17Plan<'a> {
    pub(crate) identity: NativeIdentity17Plan<'a>,
    pub(crate) authority: &'a [u8],
    pub(crate) original: Option<&'a [u8]>,
}

impl<'a> NativeToken17Plan<'a> {
    pub(crate) fn validate(
        input: &'a [u8],
        kind: NativeToken17Kind,
    ) -> Result<Self, ProviderError> {
        let mut fields = Fields::object(input)?;
        if kind != NativeToken17Kind::Ack {
            exact_text(
                fields.named("attempt_role")?,
                match kind {
                    NativeToken17Kind::Prepare => "native-complete-restore-prepare",
                    NativeToken17Kind::Commit => "native-complete-restore-commit",
                    NativeToken17Kind::Ack => return Err(invalid()),
                },
            )?;
        }
        let authority = fields.named("authority")?;
        exact_text(fields.named("boot_role")?, "native-boot")?;
        let identity = NativeIdentity17Plan::validate(
            fields.named("identity")?,
            kind == NativeToken17Kind::Ack,
        )?;
        let original = if kind == NativeToken17Kind::Ack {
            Some(fields.named("original")?)
        } else {
            None
        };
        exact_text(fields.named("policy_role")?, "native-policy")?;
        exact_text(
            fields.named("schema")?,
            match kind {
                NativeToken17Kind::Ack => "source-private.native-verified-admit-history/17",
                NativeToken17Kind::Prepare => "source-private.native-verified-prepare-history/17",
                NativeToken17Kind::Commit => "source-private.native-verified-commit-history/17",
            },
        )?;
        fields.finish()?;
        if identity.authority != authority {
            return Err(invalid());
        }
        Ok(Self {
            identity,
            authority,
            original,
        })
    }
}

pub(crate) fn installed_inputs_token_data(
    input: &[u8],
) -> Result<NativeToken17Plan<'_>, ProviderError> {
    let mut fields = Fields::object(input)?;
    exact_text(
        fields.named("custody_role")?,
        "native-restore-input-custody",
    )?;
    exact_text(
        fields.named("schema")?,
        "source-private.installed-restore-input-history/17",
    )?;
    let token = NativeToken17Plan::validate(fields.named("token")?, NativeToken17Kind::Prepare)?;
    fields.finish()?;
    Ok(token)
}

pub(crate) fn installed_commit_token_data(
    input: &[u8],
) -> Result<NativeToken17Plan<'_>, ProviderError> {
    let mut fields = Fields::object(input)?;
    exact_text(
        fields.named("mapping_role")?,
        "native-archived-protocol-mapping",
    )?;
    exact_text(
        fields.named("schema")?,
        "source-private.complete-installation-history/17",
    )?;
    let token = NativeToken17Plan::validate(fields.named("token")?, NativeToken17Kind::Commit)?;
    fields.finish()?;
    Ok(token)
}

fn exact_text(input: &[u8], expected: &str) -> Result<(), ProviderError> {
    if plain_string(input)? != expected {
        return Err(invalid());
    }
    Ok(())
}

fn quoted_u64(input: &[u8]) -> Result<u64, ProviderError> {
    unsigned(plain_string(input)?.as_bytes())
}

fn quantity(input: &[u8]) -> Result<usize, ProviderError> {
    usize::try_from(unsigned(input)?).map_err(|_| invalid())
}
