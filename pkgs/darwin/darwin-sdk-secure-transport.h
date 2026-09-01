#ifndef _SECURITY_SECURETRANSPORT_H_
#define _SECURITY_SECURETRANSPORT_H_
#include <Security/CipherSuite.h>
#include <Security/SecTrust.h>
#include <stddef.h>
__BEGIN_DECLS
struct SSLContext;
typedef struct SSLContext *SSLContextRef;
typedef const void *SSLConnectionRef;
typedef OSStatus (*SSLReadFunc)(SSLConnectionRef connection, void *data, size_t *dataLength);
typedef OSStatus (*SSLWriteFunc)(SSLConnectionRef connection, const void *data, size_t *dataLength);
typedef enum {
  kSSLSessionOptionBreakOnServerAuth = 0,
  kSSLSessionOptionFalseStart = 3,
  kSSLSessionOptionSendOneByteRecord = 4
} SSLSessionOption;
typedef enum {
  kSSLServerSide = 0,
  kSSLClientSide = 1
} SSLProtocolSide;
typedef enum {
  kSSLStreamType = 0,
  kSSLDatagramType = 1
} SSLConnectionType;
typedef enum {
  kSSLProtocolUnknown = 0,
  kSSLProtocol2 = 1,
  kSSLProtocol3 = 2,
  kSSLProtocol3Only = 3,
  kTLSProtocol1 = 4,
  kTLSProtocol1Only = 5,
  kSSLProtocolAll = 6,
  kTLSProtocol11 = 7,
  kTLSProtocol12 = 8,
  kDTLSProtocol1 = 9,
  kTLSProtocol13 = 10,
  kDTLSProtocol12 = 11,
  kTLSProtocolMaxSupported = 999
} SSLProtocol;
SSLContextRef SSLCreateContext(
  CFAllocatorRef allocator,
  SSLProtocolSide protocolSide,
  SSLConnectionType connectionType
);
OSStatus SSLSetIOFuncs(SSLContextRef context, SSLReadFunc readFunc, SSLWriteFunc writeFunc);
OSStatus SSLSetConnection(SSLContextRef context, SSLConnectionRef connection);
OSStatus SSLSetSessionOption(SSLContextRef context, SSLSessionOption option, Boolean value);
OSStatus SSLSetProtocolVersionMin(SSLContextRef context, SSLProtocol minVersion);
OSStatus SSLSetProtocolVersionMax(SSLContextRef context, SSLProtocol maxVersion);
OSStatus SSLSetPeerDomainName(SSLContextRef context, const char *peerName, size_t peerNameLength);
OSStatus SSLGetNumberSupportedCiphers(SSLContextRef context, size_t *numCiphers);
OSStatus SSLGetSupportedCiphers(SSLContextRef context, SSLCipherSuite *ciphers, size_t *numCiphers);
OSStatus SSLSetEnabledCiphers(SSLContextRef context, const SSLCipherSuite *ciphers, size_t numCiphers);
OSStatus SSLSetCertificate(SSLContextRef context, CFArrayRef __nullable certRefs);
OSStatus SSLSetPeerID(SSLContextRef context, const void * __nullable peerID, size_t peerIDLen);
OSStatus SSLGetNegotiatedCipher(SSLContextRef context, SSLCipherSuite *cipherSuite);
OSStatus SSLGetNegotiatedProtocolVersion(SSLContextRef context, SSLProtocol *protocol);
OSStatus SSLSetALPNProtocols(SSLContextRef context, CFArrayRef protocols);
OSStatus SSLCopyALPNProtocols(SSLContextRef context, CFArrayRef __nullable * __nonnull protocols);
OSStatus SSLHandshake(SSLContextRef context);
OSStatus SSLCopyPeerTrust(SSLContextRef context, SecTrustRef *trust);
OSStatus SSLWrite(SSLContextRef context, const void *data, size_t dataLength, size_t *processed);
OSStatus SSLRead(SSLContextRef context, void *data, size_t dataLength, size_t *processed);
OSStatus SSLGetBufferedReadSize(SSLContextRef context, size_t *bufferSize);
OSStatus SSLClose(SSLContextRef context);
__END_DECLS
#endif
