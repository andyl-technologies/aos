/* Checks the same header, DTLS and digest API through every link profile. */
#include <openssl/crypto.h>
#include <openssl/evp.h>
#include <openssl/opensslv.h>
#include <openssl/ssl.h>
#include <string.h>

int main(void) {
    if (strcmp(OPENSSL_VERSION_TEXT, OpenSSL_version(OPENSSL_VERSION)) != 0) {
        return 1;
    }

    SSL_CTX *context = SSL_CTX_new(DTLS_method());
    if (context == NULL) {
        return 1;
    }
    SSL_CTX_free(context);

    static const unsigned char expected[32] = {
        0xba, 0x78, 0x16, 0xbf, 0x8f, 0x01, 0xcf, 0xea,
        0x41, 0x41, 0x40, 0xde, 0x5d, 0xae, 0x22, 0x23,
        0xb0, 0x03, 0x61, 0xa3, 0x96, 0x17, 0x7a, 0x9c,
        0xb4, 0x10, 0xff, 0x61, 0xf2, 0x00, 0x15, 0xad,
    };
    unsigned char observed[EVP_MAX_MD_SIZE];
    unsigned int length = 0;
    if (EVP_Digest("abc", 3, observed, &length, EVP_sha256(), NULL) != 1) {
        return 1;
    }
    return length != sizeof(expected) || memcmp(observed, expected, sizeof(expected)) != 0;
}
