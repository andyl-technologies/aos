//! Closed transport failure labels without request URLs or error-chain values.

use tokio_rustls::rustls::{CertificateError, Error as TlsError};

/// Returns a fixed diagnostic label while discarding the protected error chain.
pub(super) fn classify(error: &reqwest::Error) -> &'static str {
    if let Some(class) = classify_chain(error) {
        return class;
    }

    if error.is_timeout() {
        "timeout"
    } else if error.is_connect() {
        "connection_failed"
    } else if error.is_body() || error.is_decode() {
        "response_body_failed"
    } else if error.is_builder() {
        "request_encoding_failed"
    } else if error.is_status() {
        "http_status_error"
    } else {
        "request_failed"
    }
}

fn classify_chain(mut current: &(dyn std::error::Error + 'static)) -> Option<&'static str> {
    for _ in 0..16 {
        if let Some(class) = classify_source(current) {
            return Some(class);
        }
        // HTTP TLS connectors nest io::Error wrappers. Their source() can
        // skip the wrapped value, so inspect get_ref() before advancing.
        current = current
            .downcast_ref::<std::io::Error>()
            .and_then(|error| error.get_ref())
            .map(|inner| inner as &(dyn std::error::Error + 'static))
            .or_else(|| current.source())?;
    }
    None
}

fn classify_source(error: &(dyn std::error::Error + 'static)) -> Option<&'static str> {
    if let Some(error) = error.downcast_ref::<TlsError>() {
        return Some(classify_tls(error));
    }
    let error = error.downcast_ref::<std::io::Error>()?;
    if let Some(error) = error
        .get_ref()
        .and_then(|inner| inner.downcast_ref::<TlsError>())
    {
        return Some(classify_tls(error));
    }
    match error.kind() {
        std::io::ErrorKind::ConnectionRefused => Some("connection_refused"),
        std::io::ErrorKind::ConnectionReset => Some("connection_reset"),
        std::io::ErrorKind::ConnectionAborted => Some("connection_aborted"),
        std::io::ErrorKind::NetworkUnreachable => Some("network_unreachable"),
        std::io::ErrorKind::HostUnreachable => Some("host_unreachable"),
        _ => None,
    }
}

fn classify_tls(error: &TlsError) -> &'static str {
    match error {
        TlsError::InvalidCertificate(error) => match error {
            CertificateError::UnknownIssuer => "tls_untrusted_certificate",
            CertificateError::Expired | CertificateError::ExpiredContext { .. } => {
                "tls_certificate_expired"
            }
            CertificateError::NotValidYet | CertificateError::NotValidYetContext { .. } => {
                "tls_certificate_not_yet_valid"
            }
            CertificateError::NotValidForName | CertificateError::NotValidForNameContext { .. } => {
                "tls_certificate_name_mismatch"
            }
            // Rustls preserves this WebPKI failure in its Other wrapper. Match
            // only its exact fixed label; never retain arbitrary error text.
            CertificateError::Other(other) if other.0.to_string() == "CaUsedAsEndEntity" => {
                "tls_ca_used_as_end_entity"
            }
            _ => "tls_invalid_certificate",
        },
        _ => "tls_handshake_failed",
    }
}

pub(super) fn request_error(error: reqwest::Error) -> anyhow::Error {
    anyhow::anyhow!(
        "provider request failed (transport_class={}); retained operation remains unknown",
        classify(&error)
    )
}

pub(super) fn response_error(error: reqwest::Error) -> anyhow::Error {
    anyhow::anyhow!(
        "provider response failed (transport_class={}); retained operation remains unknown",
        classify(&error)
    )
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn tls_classes_never_render_private_error_values() {
        let other = TlsError::InvalidCertificate(CertificateError::Other(
            tokio_rustls::rustls::OtherError(std::sync::Arc::new(std::io::Error::other(
                "https://storage.test/?X-Amz-Signature=protected-secret",
            ))),
        ));
        assert_eq!(classify_tls(&other), "tls_invalid_certificate");
        assert_eq!(
            classify_tls(&TlsError::General("protected-secret".into())),
            "tls_handshake_failed"
        );
        assert_eq!(
            classify_tls(&TlsError::InvalidCertificate(
                CertificateError::UnknownIssuer
            )),
            "tls_untrusted_certificate"
        );
    }

    #[test]
    fn io_wrapped_tls_and_fixed_ca_failure_are_classified() {
        let error = std::io::Error::new(
            std::io::ErrorKind::InvalidData,
            TlsError::InvalidCertificate(CertificateError::Other(
                tokio_rustls::rustls::OtherError(std::sync::Arc::new(std::io::Error::other(
                    "CaUsedAsEndEntity",
                ))),
            )),
        );
        assert_eq!(classify_source(&error), Some("tls_ca_used_as_end_entity"));
        let nested = std::io::Error::other(std::io::Error::other(error));
        assert_eq!(classify_chain(&nested), Some("tls_ca_used_as_end_entity"));
    }
}
