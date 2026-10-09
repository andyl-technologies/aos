use aos_sandbox_core::{PrincipalId, ProjectId};
use sha2::{Digest as _, Sha256};

const MAXIMUM_REQUEST_BYTES: usize = 1024 * 1024;
const PUBLIC_MUTATION_EFFECT_MAGIC: &[u8; 8] = b"AOSPME01";
const PUBLIC_MUTATION_EFFECT_VERSION: u16 = 1;
const PUBLIC_MUTATION_EFFECT_HEADER_BYTES: usize = 60;
const PUBLIC_MUTATION_EFFECT_DIGEST_BYTES: usize = 32;
const PUBLIC_MUTATION_EFFECT_DIGEST_DOMAIN: &[u8] = b"aos.sandbox.public-mutation-effect.v1\0";

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct InvalidPublicMutationContext(&'static str);

impl InvalidPublicMutationContext {
    pub const fn reason(self) -> &'static str {
        self.0
    }
}

impl std::fmt::Display for InvalidPublicMutationContext {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter.write_str(self.0)
    }
}

impl std::error::Error for InvalidPublicMutationContext {}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct PublicMutationContextV1 {
    caller: PrincipalId,
    project: ProjectId,
    accepted_wall_seconds: i64,
    canonical_request: Vec<u8>,
}

impl PublicMutationContextV1 {
    pub fn new(
        caller: PrincipalId,
        project: ProjectId,
        accepted_wall_seconds: i64,
        canonical_request: Vec<u8>,
    ) -> Result<Self, InvalidPublicMutationContext> {
        let encoded_length = PUBLIC_MUTATION_EFFECT_HEADER_BYTES
            .checked_add(canonical_request.len())
            .and_then(|length| length.checked_add(PUBLIC_MUTATION_EFFECT_DIGEST_BYTES));
        if caller.as_bytes() == &[0; 16]
            || project.as_bytes() == &[0; 16]
            || accepted_wall_seconds <= 0
            || canonical_request.is_empty()
            || encoded_length.is_none_or(|length| length > MAXIMUM_REQUEST_BYTES)
        {
            return Err(InvalidPublicMutationContext(
                "invalid authenticated public mutation effect",
            ));
        }

        Ok(Self {
            caller,
            project,
            accepted_wall_seconds,
            canonical_request,
        })
    }

    pub const fn caller(&self) -> PrincipalId {
        self.caller
    }

    pub const fn project(&self) -> ProjectId {
        self.project
    }

    pub const fn accepted_wall_seconds(&self) -> i64 {
        self.accepted_wall_seconds
    }

    pub fn canonical_request(&self) -> &[u8] {
        &self.canonical_request
    }

    pub fn validated_request(
        &self,
    ) -> Result<crate::public_api::request::DormantSandboxRequestKindV1, InvalidPublicMutationContext> {
        crate::public_api::mutation::PublicMutationRequestV1::decode(&self.canonical_request)
            .and_then(|request| request.decode_validated_kind())
            .map_err(|_| InvalidPublicMutationContext("invalid controller effect request"))
    }

    pub fn encode(&self) -> Result<Vec<u8>, InvalidPublicMutationContext> {
        let request_length = u32::try_from(self.canonical_request.len()).map_err(|_| {
            InvalidPublicMutationContext("public mutation effect request exceeds its bound")
        })?;
        let capacity = PUBLIC_MUTATION_EFFECT_HEADER_BYTES
            .checked_add(self.canonical_request.len())
            .and_then(|length| length.checked_add(PUBLIC_MUTATION_EFFECT_DIGEST_BYTES))
            .ok_or(InvalidPublicMutationContext(
                "public mutation effect request exceeds its bound",
            ))?;
        let mut bytes = Vec::with_capacity(capacity);
        bytes.extend_from_slice(PUBLIC_MUTATION_EFFECT_MAGIC);
        bytes.extend_from_slice(&PUBLIC_MUTATION_EFFECT_VERSION.to_be_bytes());
        bytes.extend_from_slice(&[0; 6]);
        bytes.extend_from_slice(self.caller.as_bytes());
        bytes.extend_from_slice(self.project.as_bytes());
        bytes.extend_from_slice(&self.accepted_wall_seconds.to_be_bytes());
        bytes.extend_from_slice(&request_length.to_be_bytes());
        bytes.extend_from_slice(&self.canonical_request);
        let digest: [u8; 32] = Sha256::new()
            .chain_update(PUBLIC_MUTATION_EFFECT_DIGEST_DOMAIN)
            .chain_update(&bytes)
            .finalize()
            .into();
        bytes.extend_from_slice(&digest);
        Ok(bytes)
    }

    pub fn decode(bytes: &[u8]) -> Result<Option<Self>, InvalidPublicMutationContext> {
        if !bytes.starts_with(PUBLIC_MUTATION_EFFECT_MAGIC) {
            return Ok(None);
        }
        if bytes.len() < PUBLIC_MUTATION_EFFECT_HEADER_BYTES + PUBLIC_MUTATION_EFFECT_DIGEST_BYTES
            || u16::from_be_bytes(
                bytes[8..10]
                    .try_into()
                    .map_err(|_| InvalidPublicMutationContext("invalid public mutation effect"))?,
            ) != PUBLIC_MUTATION_EFFECT_VERSION
            || bytes[10..16] != [0; 6]
        {
            return Err(InvalidPublicMutationContext(
                "invalid public mutation effect",
            ));
        }
        let caller = PrincipalId::from_bytes(
            bytes[16..32]
                .try_into()
                .map_err(|_| InvalidPublicMutationContext("invalid public mutation effect"))?,
        );
        let project = ProjectId::from_bytes(
            bytes[32..48]
                .try_into()
                .map_err(|_| InvalidPublicMutationContext("invalid public mutation effect"))?,
        );
        let accepted_wall_seconds = i64::from_be_bytes(
            bytes[48..56]
                .try_into()
                .map_err(|_| InvalidPublicMutationContext("invalid public mutation effect"))?,
        );
        let request_length = u32::from_be_bytes(
            bytes[56..60]
                .try_into()
                .map_err(|_| InvalidPublicMutationContext("invalid public mutation effect"))?,
        ) as usize;
        let request_end =
            60_usize
                .checked_add(request_length)
                .ok_or(InvalidPublicMutationContext(
                    "invalid public mutation effect",
                ))?;
        let digest_end = request_end
            .checked_add(PUBLIC_MUTATION_EFFECT_DIGEST_BYTES)
            .ok_or(InvalidPublicMutationContext(
                "invalid public mutation effect",
            ))?;
        if digest_end != bytes.len() {
            return Err(InvalidPublicMutationContext(
                "invalid public mutation effect",
            ));
        }
        let expected: [u8; 32] = Sha256::new()
            .chain_update(PUBLIC_MUTATION_EFFECT_DIGEST_DOMAIN)
            .chain_update(&bytes[..request_end])
            .finalize()
            .into();
        if bytes[request_end..] != expected {
            return Err(InvalidPublicMutationContext(
                "invalid public mutation effect",
            ));
        }

        Self::new(
            caller,
            project,
            accepted_wall_seconds,
            bytes[60..request_end].to_vec(),
        )
        .map(Some)
    }
}
