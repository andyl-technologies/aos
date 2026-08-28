#ifndef _SECURITY_SECIDENTITY_H_
#define _SECURITY_SECIDENTITY_H_
#include <Security/SecBase.h>
__BEGIN_DECLS
OSStatus SecIdentityCreateWithCertificate(
  CFTypeRef __nullable keychainOrArray,
  SecCertificateRef certificateRef,
  SecIdentityRef * __nonnull identityRef
);
OSStatus SecIdentityCopyCertificate(SecIdentityRef identityRef, SecCertificateRef *certificateRef);
OSStatus SecIdentityCopyPrivateKey(SecIdentityRef identityRef, SecKeyRef *privateKeyRef);
__END_DECLS
#endif
