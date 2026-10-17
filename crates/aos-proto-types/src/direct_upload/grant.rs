//! Exact delegated UploadPart validation without selecting network trust policy.

use std::collections::BTreeMap;

use super::validation::require;
use super::*;

impl DirectPartGrant {
    /// Checks a grant against independently retained session and part inputs.
    ///
    /// `latest_now` is the caller's conservative current-time bound. Network
    /// origin, DNS, proxy, redirect and TLS policy remain caller responsibilities;
    /// the URL is neither normalized nor replaced by this helper.
    ///
    /// # Errors
    /// Returns a value-free error for changed identities, geometry, checksums,
    /// duplicate or unexpected query/header fields, non-HTTPS URLs, malformed
    /// SigV4 coordinates, or an insufficient exclusive expiry budget.
    pub fn validate_for(
        &self,
        session: &DirectSessionRef,
        placement: &DirectPlacementRef,
        intent: &DirectUploadIntent,
        expected_part: &DirectPart,
        latest_now: u64,
        minimum_validity: u64,
    ) -> DirectUploadResult<()> {
        session.validate()?;
        placement.validate()?;
        self.part.validate(intent)?;
        require(
            self.part.checksum.algorithm == placement.checksum_algorithm,
            "direct-upload placement checksum mismatch",
        )?;
        require(
            self.session_id == session.session_id
                && self.logical_fingerprint == session.logical_fingerprint
                && &self.placement == placement
                && &self.part == expected_part,
            "direct-upload grant correlation mismatch",
        )?;
        require(
            valid_direct_digest(&self.grant_id)
                && self.grant_revision.get() > 0
                && self.method == "PUT",
            "invalid direct-upload grant identity",
        )?;
        let deadline = latest_now
            .checked_add(minimum_validity)
            .ok_or(DirectUploadError("direct-upload grant clock overflow"))?;
        require(
            deadline < self.expires_at.get(),
            "direct-upload grant expired",
        )?;
        require(
            self.url.len() <= MAX_DIRECT_GRANT_URL_BYTES
                && self.url.trim() == self.url
                && !self.url.chars().any(char::is_control),
            "direct-upload grant URL exceeds limit",
        )?;
        let url = url::Url::parse(&self.url)
            .map_err(|_| DirectUploadError("invalid direct-upload grant URL"))?;
        require(
            url.scheme() == "https"
                && url.host_str().is_some()
                && url.username().is_empty()
                && url.password().is_none()
                && url.fragment().is_none()
                && url.path() != "/",
            "invalid direct-upload grant URL",
        )?;

        let mut query = BTreeMap::new();
        for (name, value) in url.query_pairs() {
            require(
                query.len() < 9
                    && query
                        .insert(name.into_owned(), value.into_owned())
                        .is_none(),
                "duplicate direct-upload grant query",
            )?;
        }
        let mandatory = [
            "X-Amz-Algorithm",
            "X-Amz-Credential",
            "X-Amz-Date",
            "X-Amz-Expires",
            "X-Amz-Signature",
            "X-Amz-SignedHeaders",
            "partNumber",
            "uploadId",
        ];
        require(
            mandatory.iter().all(|name| query.contains_key(*name))
                && query.keys().all(|name| {
                    mandatory.contains(&name.as_str()) || name == "X-Amz-Security-Token"
                }),
            "unexpected direct-upload grant query",
        )?;
        let get = |name: &str| {
            query
                .get(name)
                .map(String::as_str)
                .ok_or(DirectUploadError("missing direct-upload grant query"))
        };
        require(
            get("X-Amz-Algorithm")? == "AWS4-HMAC-SHA256"
                && valid_direct_digest(get("X-Amz-Signature")?)
                && get("partNumber")? == self.part.part_number.to_string(),
            "invalid direct-upload grant signature coordinates",
        )?;
        let upload_id = get("uploadId")?;
        require(
            !upload_id.is_empty()
                && upload_id.len() <= 2048
                && !upload_id.chars().any(char::is_control),
            "invalid direct-upload provider session",
        )?;
        if let Some(token) = query.get("X-Amz-Security-Token") {
            require(
                !token.is_empty() && token.len() <= 4096 && !token.chars().any(char::is_control),
                "invalid direct-upload security token",
            )?;
        }
        let date = get("X-Amz-Date")?;
        let signed_at = sigv4_timestamp(date)?;
        let expiry = get("X-Amz-Expires")?;
        require(
            !expiry.starts_with('0')
                && expiry.len() <= 6
                && expiry.bytes().all(|b| b.is_ascii_digit()),
            "invalid direct-upload signature expiry",
        )?;
        let expiry: u64 = expiry
            .parse()
            .map_err(|_| DirectUploadError("invalid direct-upload signature expiry"))?;
        require(
            (1..=604_800).contains(&expiry)
                && signed_at <= latest_now
                && signed_at.checked_add(expiry) == Some(self.expires_at.get()),
            "direct-upload signature expiry mismatch",
        )?;
        let credential: Vec<_> = get("X-Amz-Credential")?.split('/').collect();
        require(
            credential.len() == 5
                && valid_direct_identity(credential[0])
                && credential[1] == &date[..8]
                && valid_direct_identity(credential[2])
                && credential[3] == "s3"
                && credential[4] == "aws4_request",
            "invalid direct-upload credential scope",
        )?;

        require(
            self.required_headers.len() == 2,
            "invalid direct-upload grant headers",
        )?;
        let mut headers = BTreeMap::new();
        for header in &self.required_headers {
            require(
                headers
                    .insert(header.name.as_str(), header.value.as_str())
                    .is_none(),
                "duplicate direct-upload grant header",
            )?;
        }
        require(
            headers.get("content-length").copied()
                == Some(self.part.byte_size.get().to_string().as_str())
                && headers.get(self.part.checksum.header_name()).copied()
                    == Some(self.part.checksum.value.as_str()),
            "direct-upload grant header mismatch",
        )?;
        let mut signed = vec!["content-length", "host", self.part.checksum.header_name()];
        signed.sort_unstable();
        require(
            get("X-Amz-SignedHeaders")? == signed.join(";"),
            "direct-upload signed headers mismatch",
        )
    }
}

fn sigv4_timestamp(value: &str) -> DirectUploadResult<u64> {
    let bytes = value.as_bytes();
    require(
        bytes.len() == 16
            && bytes[8] == b'T'
            && bytes[15] == b'Z'
            && bytes
                .iter()
                .enumerate()
                .all(|(i, b)| i == 8 || i == 15 || b.is_ascii_digit()),
        "invalid direct-upload signing timestamp",
    )?;
    let number = |start: usize, end: usize| {
        value[start..end]
            .parse::<i64>()
            .map_err(|_| DirectUploadError("invalid direct-upload signing timestamp"))
    };
    let (year, month, day) = (number(0, 4)?, number(4, 6)?, number(6, 8)?);
    let (hour, minute, second) = (number(9, 11)?, number(11, 13)?, number(13, 15)?);
    let leap = year % 4 == 0 && (year % 100 != 0 || year % 400 == 0);
    let days = match month {
        2 if leap => 29,
        2 => 28,
        4 | 6 | 9 | 11 => 30,
        1 | 3 | 5 | 7 | 8 | 10 | 12 => 31,
        _ => 0,
    };
    require(
        year >= 1970 && day > 0 && day <= days && hour < 24 && minute < 60 && second < 60,
        "invalid direct-upload signing timestamp",
    )?;
    let y = year - i64::from(month <= 2);
    let era = y / 400;
    let yoe = y - era * 400;
    let m = month + if month > 2 { -3 } else { 9 };
    let doe = yoe * 365 + yoe / 4 - yoe / 100 + (153 * m + 2) / 5 + day - 1;
    let unix_days = era * 146097 + doe - 719468;
    u64::try_from(unix_days * 86400 + hour * 3600 + minute * 60 + second)
        .map_err(|_| DirectUploadError("direct-upload signing timestamp overflow"))
}
