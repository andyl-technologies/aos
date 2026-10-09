// Exercises certificate-name handling through Folly's public SSL interface.
#include <arpa/inet.h>
#include <memory>
#include <openssl/x509v3.h>

#include <folly/io/async/ssl/OpenSSLUtils.h>
#include <folly/ssl/OpenSSLCertUtils.h>

bool matchesIPv4(X509* certificate, const char* address) {
  sockaddr_in endpoint{};
  endpoint.sin_family = AF_INET;
  if (inet_pton(AF_INET, address, &endpoint.sin_addr) != 1) {
    return false;
  }

  return folly::ssl::OpenSSLUtils::validatePeerCertNames(
      certificate, reinterpret_cast<const sockaddr*>(&endpoint), sizeof(endpoint));
}

bool matchesIPv6(X509* certificate, const char* address) {
  sockaddr_in6 endpoint{};
  endpoint.sin6_family = AF_INET6;
  if (inet_pton(AF_INET6, address, &endpoint.sin6_addr) != 1) {
    return false;
  }

  return folly::ssl::OpenSSLUtils::validatePeerCertNames(
      certificate, reinterpret_cast<const sockaddr*>(&endpoint), sizeof(endpoint));
}

int main() {
  std::unique_ptr<X509, decltype(&X509_free)> certificate(X509_new(), X509_free);
  std::unique_ptr<X509_NAME, decltype(&X509_NAME_free)> subject(
      X509_NAME_new(), X509_NAME_free);
  if (!certificate || !subject) {
    return 1;
  }

  const auto* commonName = reinterpret_cast<const unsigned char*>("dispatch.example");
  if (X509_NAME_add_entry_by_txt(
          subject.get(), "CN", MBSTRING_ASC, commonName, -1, -1, 0) != 1 ||
      X509_set_subject_name(certificate.get(), subject.get()) != 1 ||
      X509_set_issuer_name(certificate.get(), subject.get()) != 1) {
    return 2;
  }

  char alternatives[] = "IP:192.0.2.1,IP:2001:db8::1";
  std::unique_ptr<X509_EXTENSION, decltype(&X509_EXTENSION_free)> extension(
      X509V3_EXT_conf_nid(nullptr, nullptr, NID_subject_alt_name, alternatives),
      X509_EXTENSION_free);
  if (!extension || X509_add_ext(certificate.get(), extension.get(), -1) != 1) {
    return 3;
  }

  if (folly::ssl::OpenSSLUtils::getCommonName(certificate.get()) != "dispatch.example" ||
      !matchesIPv4(certificate.get(), "192.0.2.1") ||
      matchesIPv4(certificate.get(), "192.0.2.2") ||
      !matchesIPv6(certificate.get(), "2001:db8::1") ||
      matchesIPv6(certificate.get(), "2001:db8::2")) {
    return 4;
  }

  const auto commonNameValue = folly::ssl::OpenSSLCertUtils::getCommonName(*certificate);
  const auto issuerNameValue = folly::ssl::OpenSSLCertUtils::getIssuerCommonName(*certificate);
  const auto extensions = folly::ssl::OpenSSLCertUtils::getAllExtensions(*certificate);
  const auto alternativeNames =
      folly::ssl::OpenSSLCertUtils::getExtension(*certificate, "2.5.29.17");
  if (!commonNameValue || *commonNameValue != "dispatch.example" ||
      !issuerNameValue || *issuerNameValue != "dispatch.example" ||
      extensions.size() != 1 || extensions.front().first != "2.5.29.17" ||
      alternativeNames.size() != 1 || alternativeNames.front().empty()) {
    return 5;
  }

  return 0;
}
