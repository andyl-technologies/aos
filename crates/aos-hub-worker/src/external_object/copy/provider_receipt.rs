//! Exact provider Create acknowledgement and multipart manifest text.
//!
//! A successful HTTP status alone is not a positive Create receipt. The
//! response must name the signed destination bucket/key and one upload ID.

use anyhow::{ensure, Result};

/// Parses only a scoped positive CreateMultipartUpload response.
///
/// # Errors
/// Refuses error/foreign roots, duplicate fields, another destination or invalid IDs.
pub(super) fn created(xml: &str, bucket: &str, key: &str) -> Result<String> {
    let mut xml = xml.trim();
    if xml.starts_with("<?xml ") {
        let end = xml
            .find("?>")
            .ok_or_else(|| anyhow::anyhow!("Create XML declaration incomplete"))?;
        xml = xml[end + 2..].trim_start();
    }
    let start = "<InitiateMultipartUploadResult";
    ensure!(
        xml.starts_with(start)
            && xml.ends_with("</InitiateMultipartUploadResult>")
            && matches!(xml.as_bytes().get(start.len()), Some(b'>' | b' '))
            && !xml.contains("<!")
            && !xml.contains("<Error")
            && xml.matches(start).count() == 1,
        "Create response is not a positive scoped result"
    );
    ensure!(
        field(xml, "Bucket")? == bucket && field(xml, "Key")? == key,
        "Create response names another destination"
    );
    aos_hub_core::s3surface::parse_multipart_upload_id(xml)
}

fn field(xml: &str, name: &str) -> Result<String> {
    let start = format!("<{name}>");
    let end = format!("</{name}>");
    ensure!(
        xml.matches(&start).count() == 1 && xml.matches(&end).count() == 1,
        "Create response field absent or duplicated"
    );
    let begin = xml
        .find(&start)
        .ok_or_else(|| anyhow::anyhow!("Create field absent"))?
        + start.len();
    let end = xml[begin..]
        .find(&end)
        .ok_or_else(|| anyhow::anyhow!("Create field unterminated"))?
        + begin;
    let raw = &xml[begin..end];
    ensure!(
        !raw.contains('<') && !raw.contains('>'),
        "Create field contains markup"
    );
    let mut result = String::new();
    let mut remaining = raw;
    while let Some(position) = remaining.find('&') {
        result.push_str(&remaining[..position]);
        let tail = &remaining[position..];
        let (entity, decoded) = [
            ("&amp;", '&'),
            ("&quot;", '"'),
            ("&apos;", '\''),
            ("&lt;", '<'),
            ("&gt;", '>'),
        ]
        .into_iter()
        .find(|(entity, _)| tail.starts_with(entity))
        .ok_or_else(|| anyhow::anyhow!("Create field has an unsupported entity"))?;
        result.push(decoded);
        remaining = &tail[entity.len()..];
    }
    result.push_str(remaining);
    Ok(result)
}

/// Escapes a retained provider ETag as XML text without changing its value.
pub(super) fn xml_text(value: &str) -> String {
    value
        .replace('&', "&amp;")
        .replace('<', "&lt;")
        .replace('>', "&gt;")
        .replace('"', "&quot;")
        .replace('\'', "&apos;")
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn create_receipt_requires_exact_destination_and_positive_root() {
        let response = "<InitiateMultipartUploadResult xmlns=\"http://s3.amazonaws.com/doc/2006-03-01/\"><Bucket>fixture-bucket</Bucket><Key>source&amp;destination/nar</Key><UploadId>actual-positive-upload</UploadId></InitiateMultipartUploadResult>";
        assert_eq!(
            created(response, "fixture-bucket", "source&destination/nar").unwrap(),
            "actual-positive-upload"
        );
        assert!(created(response, "other-bucket", "source&destination/nar").is_err());
        assert!(created(response, "fixture-bucket", "replacement/nar").is_err());
        assert!(
            created(
                &response.replace("InitiateMultipartUploadResult", "Error"),
                "fixture-bucket",
                "source&destination/nar"
            )
            .is_err()
        );
        assert!(
            created(
                &response.replace("</Bucket>", "</Bucket><Bucket>fixture-bucket</Bucket>"),
                "fixture-bucket",
                "source&destination/nar"
            )
            .is_err()
        );
        assert_eq!(xml_text("\"part<&>\""), "&quot;part&lt;&amp;&gt;&quot;");
    }
}
