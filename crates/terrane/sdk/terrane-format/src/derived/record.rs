//! Encodes the closed derived-attribute registry and versioned record schema.
//!
//! ```text
//! {1: bstr32, 2: name, 3: value, 4: "function/version", 5: bstr32, ?6: bstr64}
//! ```

use super::{Error, Magic};
use crate::{
    cbor::{self, Decoder},
    identity::{Digest, Identity, IdentityKind, TERRANE_V1},
};
use alloc::{
    string::{String, ToString},
    vec::Vec,
};

/// A registered per-object derived or dictionary-selection attribute.
#[derive(Clone, Copy, Debug, Eq, Ord, PartialEq, PartialOrd)]
pub enum AttributeName {
    /// SHA-256 over the full plaintext.
    Sha256,
    /// SHA-512 over the full plaintext.
    Sha512,
    /// Git blob SHA-1, including its length header.
    GitBlobSha1,
    /// Git blob SHA-256, including its length header.
    GitBlobSha256,
    /// Bounded content magic classification.
    Magic,
    /// ELF header and dynamic linkage classification.
    Elf,
    /// Shebang interpreter and optional argument.
    Shebang,
    /// A deployment-selected standalone dictionary chunk identity.
    ZstdDictionary,
}

impl AttributeName {
    /// Returns the registered attribute spelling.
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::Sha256 => "hash.sha256",
            Self::Sha512 => "hash.sha512",
            Self::GitBlobSha1 => "hash.git-blob-sha1",
            Self::GitBlobSha256 => "hash.git-blob-sha256",
            Self::Magic => "class.magic",
            Self::Elf => "class.elf",
            Self::Shebang => "class.shebang",
            Self::ZstdDictionary => "zstd-dictionary",
        }
    }

    /// Resolves a name in the closed derived-attribute registry.
    ///
    /// # Errors
    /// Returns [`Error::UnknownAttribute`] for unregistered names.
    pub fn parse(name: &str) -> Result<Self, Error> {
        match name {
            "hash.sha256" => Ok(Self::Sha256),
            "hash.sha512" => Ok(Self::Sha512),
            "hash.git-blob-sha1" => Ok(Self::GitBlobSha1),
            "hash.git-blob-sha256" => Ok(Self::GitBlobSha256),
            "class.magic" => Ok(Self::Magic),
            "class.elf" => Ok(Self::Elf),
            "class.shebang" => Ok(Self::Shebang),
            "zstd-dictionary" => Ok(Self::ZstdDictionary),
            _ => Err(Error::UnknownAttribute),
        }
    }

    /// Returns the initial implemented function metadata.
    ///
    /// `zstd-dictionary/1` records an explicit deployment choice, whose value
    /// cannot be recomputed from the object's plaintext alone.
    pub fn function(self) -> Function {
        Function {
            name: match self {
                Self::Sha256 => "sha256",
                Self::Sha512 => "sha512",
                Self::GitBlobSha1 => "git-blob-sha1",
                Self::GitBlobSha256 => "git-blob-sha256",
                Self::Magic => "magic",
                Self::Elf => "elf",
                Self::Shebang => "shebang",
                Self::ZstdDictionary => "zstd-dictionary",
            }
            .to_string(),
            version: "1".to_string(),
        }
    }
}

/// The exact name and version of a producing or dictionary-selection function.
#[derive(Clone, Debug, Eq, Ord, PartialEq, PartialOrd)]
pub struct Function {
    /// The producing function name, without a slash.
    pub name: String,
    /// The immutable version, without a slash.
    pub version: String,
}

impl Function {
    /// Reports whether this exact function metadata is understood.
    pub fn supported(&self, attribute: AttributeName) -> bool {
        *self == attribute.function()
    }

    fn validate(&self) -> Result<(), Error> {
        if [&self.name, &self.version].iter().any(|part| {
            part.is_empty()
                || part.len() > 128
                || !part
                    .bytes()
                    .all(|b| b.is_ascii_alphanumeric() || matches!(b, b'-' | b'.' | b'_'))
        }) {
            return Err(Error::InvalidFunction);
        }
        Ok(())
    }
}

/// Parsed ELF metadata represented by the registry's five integer keys.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct ElfValue {
    /// ELF word size, either 32 or 64.
    pub class: u8,
    /// ELF `e_machine`, without host-dependent interpretation.
    pub machine: u16,
    /// ELF `e_type`, without host-dependent interpretation.
    pub elf_type: u16,
    /// The exact UTF-8 PT_INTERP string when present.
    pub interpreter: Option<String>,
    /// DT_NEEDED strings in their dynamic-table order, including duplicates.
    pub needed: Vec<String>,
}

/// A first-line interpreter and optional unsplit interpreter argument.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct ShebangValue {
    /// The absolute interpreter path.
    pub interpreter: String,
    /// The trimmed remainder of the first line, if nonempty.
    pub argument: Option<String>,
}

/// A typed value in the registered per-object attribute set.
#[derive(Clone, Debug, Eq, PartialEq)]
pub enum AttributeValue {
    /// A full-plaintext SHA-256 digest.
    Sha256([u8; 32]),
    /// A full-plaintext SHA-512 digest.
    Sha512([u8; 64]),
    /// A Git blob SHA-1 digest.
    GitBlobSha1([u8; 20]),
    /// A Git blob SHA-256 digest.
    GitBlobSha256([u8; 32]),
    /// A bounded classifier result.
    Magic(Magic),
    /// ELF format metadata.
    Elf(ElfValue),
    /// First-line interpreter metadata.
    Shebang(ShebangValue),
    /// The chunk-domain digest of a supplied standalone dictionary.
    ZstdDictionary(Digest),
}

impl AttributeValue {
    /// Returns the attribute whose schema owns this value.
    pub const fn name(&self) -> AttributeName {
        match self {
            Self::Sha256(_) => AttributeName::Sha256,
            Self::Sha512(_) => AttributeName::Sha512,
            Self::GitBlobSha1(_) => AttributeName::GitBlobSha1,
            Self::GitBlobSha256(_) => AttributeName::GitBlobSha256,
            Self::Magic(_) => AttributeName::Magic,
            Self::Elf(_) => AttributeName::Elf,
            Self::Shebang(_) => AttributeName::Shebang,
            Self::ZstdDictionary(_) => AttributeName::ZstdDictionary,
        }
    }

    /// Encodes the registry's canonical value, suitable for an inline copy.
    ///
    /// # Errors
    /// Returns [`Error::InvalidValue`] for an invalid ELF class or string.
    pub fn encode(&self) -> Result<Vec<u8>, Error> {
        let mut out = Vec::new();
        self.write(&mut out)?;
        Ok(out)
    }

    fn write(&self, out: &mut Vec<u8>) -> Result<(), Error> {
        match self {
            Self::Sha256(v) | Self::GitBlobSha256(v) | Self::ZstdDictionary(v) => {
                cbor::write_bytes(out, v);
            }
            Self::Sha512(v) => cbor::write_bytes(out, v),
            Self::GitBlobSha1(v) => cbor::write_bytes(out, v),
            Self::Magic(v) => cbor::write_text(out, v.as_str()),
            Self::Elf(v) => {
                if !matches!(v.class, 32 | 64) {
                    return Err(Error::InvalidValue);
                }
                validate_optional(&v.interpreter)?;
                for name in &v.needed {
                    validate_string(name)?;
                }
                cbor::write_map(out, 5);
                for (key, value) in [
                    (1, u64::from(v.class)),
                    (2, u64::from(v.machine)),
                    (3, u64::from(v.elf_type)),
                ] {
                    cbor::write_uint(out, key);
                    cbor::write_uint(out, value);
                }
                cbor::write_uint(out, 4);
                write_optional(out, &v.interpreter);
                cbor::write_uint(out, 5);
                cbor::write_array(out, v.needed.len());
                for name in &v.needed {
                    cbor::write_text(out, name);
                }
            }
            Self::Shebang(v) => {
                validate_string(&v.interpreter)?;
                if !v.interpreter.starts_with('/') {
                    return Err(Error::InvalidValue);
                }
                validate_optional(&v.argument)?;
                cbor::write_map(out, 2);
                cbor::write_uint(out, 1);
                cbor::write_text(out, &v.interpreter);
                cbor::write_uint(out, 2);
                write_optional(out, &v.argument);
            }
        }
        Ok(())
    }

    /// Decodes one canonical typed value and rejects trailing bytes.
    ///
    /// # Errors
    /// Returns a CBOR or value-schema error on invalid input.
    pub fn decode(name: AttributeName, bytes: &[u8]) -> Result<Self, Error> {
        let mut decoder = Decoder::new(bytes);
        let value = Self::read(name, &mut decoder)?;
        decoder.finish()?;
        value.encode()?;
        Ok(value)
    }

    fn read(name: AttributeName, d: &mut Decoder<'_>) -> Result<Self, Error> {
        Ok(match name {
            AttributeName::Sha256 => {
                Self::Sha256(d.bytes(32)?.try_into().map_err(|_| Error::InvalidValue)?)
            }
            AttributeName::Sha512 => {
                Self::Sha512(d.bytes(64)?.try_into().map_err(|_| Error::InvalidValue)?)
            }
            AttributeName::GitBlobSha1 => {
                Self::GitBlobSha1(d.bytes(20)?.try_into().map_err(|_| Error::InvalidValue)?)
            }
            AttributeName::GitBlobSha256 => {
                Self::GitBlobSha256(d.bytes(32)?.try_into().map_err(|_| Error::InvalidValue)?)
            }
            AttributeName::ZstdDictionary => {
                Self::ZstdDictionary(d.bytes(32)?.try_into().map_err(|_| Error::InvalidValue)?)
            }
            AttributeName::Magic => Self::Magic(Magic::parse(d.text(16)?)?),
            AttributeName::Elf => {
                if d.map(5)? != 5 {
                    return Err(Error::InvalidValue);
                }
                key(d, 1)?;
                let class = u8::try_from(d.uint()?).map_err(|_| Error::InvalidValue)?;
                key(d, 2)?;
                let machine = u16::try_from(d.uint()?).map_err(|_| Error::InvalidValue)?;
                key(d, 3)?;
                let elf_type = u16::try_from(d.uint()?).map_err(|_| Error::InvalidValue)?;
                key(d, 4)?;
                let interpreter = read_optional(d)?;
                key(d, 5)?;
                let count = d.array(d.remaining().len())?;
                let mut needed = Vec::new();
                for _ in 0..count {
                    needed.push(d.text(65536)?.to_string());
                }
                Self::Elf(ElfValue {
                    class,
                    machine,
                    elf_type,
                    interpreter,
                    needed,
                })
            }
            AttributeName::Shebang => {
                if d.map(2)? != 2 {
                    return Err(Error::InvalidValue);
                }
                key(d, 1)?;
                let interpreter = d.text(65536)?.to_string();
                key(d, 2)?;
                let argument = read_optional(d)?;
                Self::Shebang(ShebangValue {
                    interpreter,
                    argument,
                })
            }
        })
    }
}

fn validate_string(value: &str) -> Result<(), Error> {
    if value.is_empty() || value.len() > 65536 || value.as_bytes().contains(&0) {
        return Err(Error::InvalidValue);
    }
    Ok(())
}

fn validate_optional(value: &Option<String>) -> Result<(), Error> {
    if let Some(value) = value {
        validate_string(value)?;
    }
    Ok(())
}

fn write_optional(out: &mut Vec<u8>, value: &Option<String>) {
    if let Some(value) = value {
        cbor::write_text(out, value);
    } else {
        out.push(0xf6);
    }
}

fn read_optional(d: &mut Decoder<'_>) -> Result<Option<String>, Error> {
    if d.peek_major()? == 7 {
        if d.simple()? != 0xf6 {
            return Err(Error::InvalidValue);
        }
        Ok(None)
    } else {
        Ok(Some(d.text(65536)?.to_string()))
    }
}

fn key(d: &mut Decoder<'_>, expected: u64) -> Result<(), Error> {
    if d.uint()? != expected {
        return Err(Error::InvalidValue);
    }
    Ok(())
}

/// A content-addressed attribute with separately retained producer provenance.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct AttrRecord {
    /// Manifest or inline chunk digest identifying the object.
    pub object: Digest,
    /// The registered attribute and its typed value.
    pub value: AttributeValue,
    /// The exact producing function; unknown versions remain unverified.
    pub function: Function,
    /// The final identity of the commit that produced the attribute.
    pub producer: Digest,
    /// Optional detached signature by the verified producer's terminal key.
    pub signature: Option<[u8; 64]>,
}

impl AttrRecord {
    /// Constructs a record with the implemented initial function metadata.
    pub fn new(object: Digest, value: AttributeValue, producer: Digest) -> Self {
        let function = value.name().function();
        Self {
            object,
            value,
            function,
            producer,
            signature: None,
        }
    }

    /// Encodes the canonical AttrRecord, including its optional detached signature.
    ///
    /// # Errors
    /// Returns a value or function-schema error for invalid fields.
    pub fn encode(&self) -> Result<Vec<u8>, Error> {
        let mut out = Vec::new();
        cbor::write_map(&mut out, if self.signature.is_some() { 6 } else { 5 });
        self.write_fields(&mut out)?;
        if let Some(signature) = self.signature {
            cbor::write_uint(&mut out, 6);
            cbor::write_bytes(&mut out, &signature);
        }
        Ok(out)
    }

    fn write_fields(&self, out: &mut Vec<u8>) -> Result<(), Error> {
        self.function.validate()?;
        cbor::write_uint(out, 1);
        cbor::write_bytes(out, &self.object);
        cbor::write_uint(out, 2);
        cbor::write_text(out, self.value.name().as_str());
        cbor::write_uint(out, 3);
        self.value.write(out)?;
        cbor::write_uint(out, 4);
        cbor::write_text(
            out,
            &alloc::format!("{}/{}", self.function.name, self.function.version),
        );
        cbor::write_uint(out, 5);
        cbor::write_bytes(out, &self.producer);
        Ok(())
    }

    /// Encodes the domain-separated detached-signature preimage.
    ///
    /// The signature field is always absent from the signed canonical map.
    ///
    /// # Errors
    /// Returns a value or function-schema error for invalid fields.
    pub fn signature_preimage(&self) -> Result<Vec<u8>, Error> {
        let mut out = b"terrane-attr-signature-v1\0".to_vec();
        cbor::write_map(&mut out, 5);
        self.write_fields(&mut out)?;
        Ok(out)
    }

    /// Signs the record with the terminal secret of its already verified producer.
    ///
    /// This creates immutable signature bytes, not tree/object provenance evidence.
    /// [`super::verify_record_producer`] additionally checks the producer's witness.
    ///
    /// # Errors
    /// Returns a schema error, or [`Error::InvalidProvenance`] when the producer
    /// identity or terminal key differs from the configured verified commit.
    pub fn sign(
        &mut self,
        producer: &crate::provenance::VerifiedCommit,
        secret: &[u8; 32],
    ) -> Result<(), Error> {
        use ed25519_dalek::{Signer, SigningKey};

        let key = SigningKey::from_bytes(secret);
        if producer.identity() != self.producer
            || key.verifying_key().to_bytes() != producer.signing_public_key()
        {
            return Err(Error::InvalidProvenance);
        }
        self.signature = Some(key.sign(&self.signature_preimage()?).to_bytes());
        Ok(())
    }

    /// Checks the detached signature against a supplied terminal public key.
    ///
    /// This proves only the signature binding. Producer attribution also needs
    /// verified commit history and a canonical reachable object witness.
    ///
    /// # Errors
    /// Returns a schema error or [`Error::InvalidProvenance`] for an absent,
    /// malformed, or invalid signature or public key.
    pub fn verify_signature(&self, public_key: &[u8; 32]) -> Result<(), Error> {
        use ed25519_dalek::{Signature, VerifyingKey};

        let signature = self.signature.ok_or(Error::InvalidProvenance)?;
        let key = VerifyingKey::from_bytes(public_key).map_err(|_| Error::InvalidProvenance)?;
        key.verify_strict(
            &self.signature_preimage()?,
            &Signature::from_bytes(&signature),
        )
        .map_err(|_| Error::InvalidProvenance)
    }

    /// Decodes a canonical record while retaining unsupported function versions.
    ///
    /// # Errors
    /// Rejects wrong keys, types, registry names, noncanonical CBOR, or trailers.
    pub fn decode(bytes: &[u8]) -> Result<Self, Error> {
        let mut d = Decoder::new(bytes);
        let fields = d.map(6)?;
        if fields != 5 && fields != 6 {
            return Err(Error::InvalidValue);
        }
        key(&mut d, 1)?;
        let object = d.bytes(32)?.try_into().map_err(|_| Error::InvalidValue)?;
        key(&mut d, 2)?;
        let name = AttributeName::parse(d.text(128)?)?;
        key(&mut d, 3)?;
        let value = AttributeValue::read(name, &mut d)?;
        key(&mut d, 4)?;
        let function = d.text(257)?;
        let (function_name, version) = function.split_once('/').ok_or(Error::InvalidFunction)?;
        let function = Function {
            name: function_name.to_string(),
            version: version.to_string(),
        };
        key(&mut d, 5)?;
        let producer = d.bytes(32)?.try_into().map_err(|_| Error::InvalidValue)?;
        let signature = if fields == 6 {
            key(&mut d, 6)?;
            Some(d.bytes(64)?.try_into().map_err(|_| Error::InvalidValue)?)
        } else {
            None
        };
        d.finish()?;
        let record = Self {
            object,
            value,
            function,
            producer,
            signature,
        };
        record.encode()?;
        Ok(record)
    }

    /// Calculates the domain-separated identity of the canonical record.
    ///
    /// # Errors
    /// Returns a schema or identity-profile error.
    pub fn identity(&self) -> Result<Identity, Error> {
        Ok(TERRANE_V1.calculate(IdentityKind::Attribute, &self.encode()?)?)
    }

    /// Checks the canonical inline copy against this record's value.
    ///
    /// # Errors
    /// Returns a typed decoding failure or [`Error::InlineDisagreement`].
    pub fn agree_inline(&self, bytes: &[u8]) -> Result<(), Error> {
        if AttributeValue::decode(self.value.name(), bytes)? != self.value {
            return Err(Error::InlineDisagreement);
        }
        Ok(())
    }

    /// Checks a recomputation under the exact implemented function version.
    ///
    /// Deployment-supplied dictionary selections have no plaintext-only
    /// recomputation and return [`Error::UnsupportedFunction`].
    ///
    /// # Errors
    /// Returns [`Error::UnsupportedFunction`] or [`Error::InvalidValue`] on disagreement.
    pub fn verify_value(&self, computed: &AttributeValue) -> Result<(), Error> {
        // A deployment choice is authenticated metadata, not a function of
        // the object's plaintext. Equality cannot establish recomputation.
        if self.value.name() == AttributeName::ZstdDictionary
            || !self.function.supported(self.value.name())
        {
            return Err(Error::UnsupportedFunction);
        }
        if computed != &self.value {
            return Err(Error::InvalidValue);
        }
        Ok(())
    }
}
