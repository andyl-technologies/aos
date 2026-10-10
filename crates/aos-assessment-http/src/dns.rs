//! Connect-time DNS pinning for the fixed installed public source profiles.

use std::net::SocketAddr;

use reqwest::dns::{Addrs, Name, Resolve, Resolving};

pub(super) struct PublicSourceResolver;

impl Resolve for PublicSourceResolver {
    fn resolve(&self, name: Name) -> Resolving {
        let host = name.as_str().to_owned();
        Box::pin(async move {
            if !matches!(
                host.as_str(),
                "api.github.com"
                    | "api.osv.dev"
                    | "go.dev"
                    | "repology.org"
                    | "services.nvd.nist.gov"
                    | "www.cisa.gov"
            ) {
                return Err(refused(
                    "source DNS name differs from installed public profiles",
                ));
            }
            let answers = tokio::net::lookup_host((host.as_str(), 443))
                .await
                .map_err(|_| refused("source DNS resolution is unavailable"))?
                .take(33)
                .collect::<Vec<_>>();
            validate_answers(&answers)?;
            // The connector consumes these already checked addresses directly.
            // It never performs a second resolution after the policy check.
            Ok(Box::new(answers.into_iter()) as Addrs)
        })
    }
}

fn validate_answers(
    answers: &[SocketAddr],
) -> Result<(), Box<dyn std::error::Error + Send + Sync>> {
    if answers.is_empty()
        || answers.len() > 32
        || answers
            .iter()
            .any(|address| !aos_contract::network_address::is_global_ip(address.ip()))
    {
        return Err(refused(
            "source DNS answer set is empty, excessive or non-public",
        ));
    }
    Ok(())
}

fn refused(message: &'static str) -> Box<dyn std::error::Error + Send + Sync> {
    Box::new(std::io::Error::new(
        std::io::ErrorKind::PermissionDenied,
        message,
    ))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn dns_answers_refuse_private_mixed_mapped_and_excessive_destinations() {
        let public: SocketAddr = "8.8.8.8:443".parse().unwrap();
        assert!(validate_answers(&[public]).is_ok());
        assert!(validate_answers(&[]).is_err());
        assert!(validate_answers(&vec![public; 33]).is_err());
        for blocked in [
            "127.0.0.1:443",
            "10.0.0.1:443",
            "169.254.169.254:443",
            "100.64.0.1:443",
            "192.0.2.1:443",
            "[::1]:443",
            "[fc00::1]:443",
            "[::ffff:127.0.0.1]:443",
        ] {
            let blocked = blocked.parse().unwrap();
            assert!(validate_answers(&[blocked]).is_err());
            assert!(validate_answers(&[public, blocked]).is_err());
        }
    }

    #[tokio::test]
    async fn uninstalled_dns_names_are_refused_before_resolution() {
        for host in ["localhost", "unrelated.invalid", "metadata.google.internal"] {
            assert!(
                PublicSourceResolver
                    .resolve(host.parse().unwrap())
                    .await
                    .is_err()
            );
        }
    }
}
